package ebpfsyncer

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/openshift/ingress-node-firewall/api/v1alpha1"
	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	nodefwloader "github.com/openshift/ingress-node-firewall/pkg/ebpf"
	intfs "github.com/openshift/ingress-node-firewall/pkg/interfaces"
	"github.com/openshift/ingress-node-firewall/pkg/metrics"

	"github.com/go-logr/logr"
	"k8s.io/client-go/util/retry"
)

var (
	once                         sync.Once
	instance                     EbpfSyncer
	isValidInterfaceNameAndState = intfs.IsValidInterfaceNameAndState
	xdpEBUSYErr                  = "device or resource busy"
)

// ebpfDaemon is a single point of contact that all reconciliation requests will send their desired state of
// interface rules to. On the other side, ebpfDaemon makes sure that rules are attached and detached from / to the
// host's interfaces.
type EbpfSyncer interface {
	SyncInterfaceIngressRules(map[string][]infv1alpha1.IngressNodeFirewallRules, bool) error
}

// getEbpfDaemon allocates and returns a single instance of ebpfSingleton. If such an instance does not yet exist,
// it sets up a new one. It will do so only once. Then, it returns the instance.
func GetEbpfSyncer(ctx context.Context, log logr.Logger, stats *metrics.Statistics, mock EbpfSyncer) EbpfSyncer {
	once.Do(func() {
		// Check if instace is nil. For mock tests, one can provide a custom instance.
		if mock == nil {
			instance = &ebpfSingleton{
				ctx:               ctx,
				log:               log,
				stats:             stats,
				managedInterfaces: make(map[string]struct{}),
			}
		} else {
			instance = mock
		}
	})
	return instance
}

// ebpfSingleton implements ebpfDaemon.
type ebpfSingleton struct {
	ctx               context.Context
	log               logr.Logger
	stats             *metrics.Statistics
	c                 *nodefwloader.IngNodeFwController
	managedInterfaces map[string]struct{}
	mu                sync.Mutex
}

// syncInterfaceIngressRules takes a map of <interfaceName>:<interfaceRules> and a boolean parameter that indicates
// if rules shall be attached to the interface or if rules shall be detached from the interface.
// If isDelete is true then all rules will be attached from all provided interfaces. In such a case, the given
// interfaceRules (if any) will be ignored.
// If isDelete is false then rules will be synchronized for each of the given interfaces.
func (e *ebpfSingleton) SyncInterfaceIngressRules(
	ifaceIngressRules map[string][]infv1alpha1.IngressNodeFirewallRules, isDelete bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	logger := e.log.WithName("syncIngressNodeFirewallResources")
	logger.Info("Running sync operation", "ifaceIngressRules", ifaceIngressRules, "isDelete", isDelete)

	sigc := make(chan os.Signal, 1)

	// Stop the poller for the time of this operation and start it again afterwards.
	if e.stats != nil {
		e.stats.StopPoll()
		defer func() {
			if e.c != nil {
				e.stats.StartPoll(e.c.GetStatisticsMap())
			}
		}()
	}

	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func(c chan os.Signal) {
		// Wait for a SIGTERM
		<-c
		if e.c != nil {
			e.resetAll()
		}
	}(sigc)

	// Create a new manager if none exists.
	if err := e.createNewManager(); err != nil {
		return err
	}

	// For delete operations, detach all interfaces and run a cleanup, set managed interfaces and the
	// manager to empty / nil values, then return.
	if isDelete {
		return e.resetAll()
	}

	// Detach unmanaged interfaces that were previously managed.
	if err := e.detachUnmanagedInterfaces(ifaceIngressRules); err != nil {
		return err
	}

	// Attach interfaces which shall now be managed.
	if err := e.attachNewInterfaces(ifaceIngressRules); err != nil {
		return err
	}

	// Load IngressNodeFirewall Rules (this is idempotent and will add new rules and purge rules that shouldn't exist).
	if err := e.loadIngressNodeFirewallRules(ifaceIngressRules); err != nil {
		return err
	}
	return nil
}

// getBPFMapContentForTest lists the content of the current BPF map. Used for unit testing only.
func (e *ebpfSingleton) getBPFMapContentForTest() (map[nodefwloader.BpfLpmIpKeySt]nodefwloader.BpfRulesValSt, error) {
	if e.c == nil {
		return nil, fmt.Errorf("Nil pointer to node firewall loader")
	}
	return e.c.GetBPFMapContentForTest()
}

// Create a new manager if none exists.
func (e *ebpfSingleton) createNewManager() error {
	var err error
	if e.c == nil {
		e.log.Info("Creating a new eBPF firewall node controller")
		if e.c, err = nodefwloader.NewIngNodeFwController(); err != nil {
			return fmt.Errorf("Failed to create nodefw controller instance, err: %q", err)
		}
	}
	return nil
}

// loadIngressNodeFirewallRules adds, updates and deletes rules from the ruleset.
func (e *ebpfSingleton) loadIngressNodeFirewallRules(
	ifaceIngressRules map[string][]v1alpha1.IngressNodeFirewallRules) error {
	e.log.Info("Loading rules")
	if err := e.c.IngressNodeFwRulesLoader(ifaceIngressRules); err != nil {
		e.log.Error(err, "Failed loading ingress firewall rules")
		return err
	}
	return nil
}

// resetAll deletes all current attachments and cleans all eBPFObjects. It then sets the ingress firewall manager
// back to nil. It also deletes all pins and removed all XDP attachments for all system interfaces.
func (e *ebpfSingleton) resetAll() error {
	e.log.Info("Running detach operation of managed interfaces")
	for intf := range e.managedInterfaces {
		err := e.c.IngressNodeFwDetach(intf)
		if err != nil {
			e.log.Info("Could not detach managed interface", "intf", intf, "err", err)
		}
	}

	e.log.Info("Closing all objects that belong to the firewall manager")
	if err := e.c.Close(); err != nil {
		e.log.Info("Could not clean up all objects that belong to the firewall manager", "err", err)
	}

	e.managedInterfaces = make(map[string]struct{})
	e.c = nil

	return nil
}

// attachNewInterfaces attaches the eBPF program to the XDP hook of unmanaged interfaces.
// It is possible that an attach operation fails with "already attached" while a previous detach operation is
// still in progress. Thus, if IngressNodeFwAttach fails, retry on error.
func (e *ebpfSingleton) attachNewInterfaces(ifaceIngressRules map[string][]v1alpha1.IngressNodeFirewallRules) error {
	for intf := range ifaceIngressRules {
		// First, check if the interface name is valid.
		if !isValidInterfaceNameAndState(intf) {
			e.log.Info("Fail to attach ingress firewall rules", "invalid interface", intf)
			continue
		}

		// Then, check if the interface is already managed.
		if _, ok := e.managedInterfaces[intf]; !ok {
			// Attach to the interfaces - in case the interface is already attached, retry.
			err := retry.OnError(
				retry.DefaultRetry,
				func(err error) bool {
					return strings.Contains(err.Error(), xdpEBUSYErr)
				},
				func() error {
					e.log.Info("Attaching firewall interface", "intf", intf)
					if err := e.c.IngressNodeFwAttach(intf); err != nil {
						e.log.Error(err, "Fail to attach ingress firewall prog")
						return err
					}
					e.managedInterfaces[intf] = struct{}{}
					return nil
				})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// detachUnmanagedInterfaces detaches any interfaces that were managed by us but that should not be managed any more.
// After this it purges all rules from the ruleset for interfaces that do not exist any more.
func (e *ebpfSingleton) detachUnmanagedInterfaces(ifaceIngressRules map[string][]infv1alpha1.IngressNodeFirewallRules) error {
	// Detach any interfaces that were managed by us but that should not be managed any more.
	e.log.Info("Comparing currently managed interfaces against list of XDP interfaces on system",
		"e.managedInterfaces", e.managedInterfaces)
	for intf := range e.managedInterfaces {
		if _, ok := ifaceIngressRules[intf]; !ok {
			e.log.Info("Running detach operation for interface", "intf", intf)
			if err := e.c.IngressNodeFwDetach(intf); err != nil {
				return err
			}
			delete(e.managedInterfaces, intf)
		}
	}
	return nil
}
