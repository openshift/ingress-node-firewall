package ebpfsyncer

import (
	"context"
	"fmt"
	"sync"

	"github.com/openshift/ingress-node-firewall/api/v1alpha1"
	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	nodefwloader "github.com/openshift/ingress-node-firewall/pkg/ebpf"
	intfs "github.com/openshift/ingress-node-firewall/pkg/interfaces"
	"github.com/openshift/ingress-node-firewall/pkg/metrics"

	"github.com/go-logr/logr"
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

	// Stop the poller for the time of this operation and start it again afterwards.
	if e.stats != nil {
		e.stats.StopPoll()
		defer func() {
			if e.c != nil {
				e.stats.StartPoll(e.c.GetStatisticsMap())
			}
		}()
	}

	// Create a new manager if none exists.
	if err := e.createNewManager(); err != nil {
		return err
	}

	// (astoycos) clear out stats map if we're deleting
	// removing/resetting the bpf program (yet).
	// For delete operations, detach all interfaces and run a cleanup, set managed interfaces and the
	// manager to empty / nil values, then return.
	if isDelete {
		e.stats.PurgeMetrics(e.c.GetStatisticsMap())
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
