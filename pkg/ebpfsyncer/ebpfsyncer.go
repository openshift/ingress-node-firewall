package ebpfsyncer

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/go-logr/logr"
	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	nodefwloader "github.com/openshift/ingress-node-firewall/pkg/ebpf"
	"github.com/openshift/ingress-node-firewall/pkg/failsaferules"
	"github.com/openshift/ingress-node-firewall/pkg/metrics"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var once sync.Once
var instance EbpfSyncer

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
// intefaceRules (if any) will be ignored.
// If isDelete is false then rules will be synchronized for each of the given interfaces.
func (e *ebpfSingleton) SyncInterfaceIngressRules(
	ifaceIngressRules map[string][]infv1alpha1.IngressNodeFirewallRules, isDelete bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	logger := e.log.WithName("syncIngressNodeFirewallResources")
	logger.Info("Running sync operation", "ifaceIngressRules", ifaceIngressRules, "isDelete", isDelete)

	if e.stats != nil {
		e.stats.StopPoll()
		defer func() {
			if e.c != nil {
				e.stats.StartPoll(e.c.GetStatisticsMap())
			}
		}()
	}

	// For delete operations, detach all interfaces and run a cleanup, set managed interfaces and the
	// manager to empty / nil values, then return.
	// TODO: This should purge all XDP attachments on all interfaces even if we are not managing them.
	// Alternatively, we need something like method XDPInterfacePurge() that would purse all unmanaged interfaces
	// both from the rules and from the interface attachements.
	if isDelete {
		logger.Info("Running detach and eBPF cleanup operation")
		for intf := range e.managedInterfaces {
			_, err := e.c.IngressNodeFwAttach([]string{intf}, true)
			if err != nil {
				return err
			}
		}
		e.managedInterfaces = make(map[string]struct{})
		err := e.c.CleaneBPFObjs()
		if err != nil {
			return err
		}
		e.c = nil

		return nil
	}

	// Create a new manager if none exists.
	var err error
	if e.c == nil {
		logger.Info("Creating a new eBPF firewall node controller")
		e.c, err = nodefwloader.NewIngNodeFwController()
		if err != nil {
			return fmt.Errorf("Fail to create nodefw controller instance, err: %q", err)
		}
	}

	// Detach any interfaces that were managed by us but that should not be managed any more.
	// Also delete the rules associated to these interfaces. See TODO below.
	for intf := range e.managedInterfaces {
		logger.Info("Running detach operation for interface", "intf", intf)
		if _, ok := ifaceIngressRules[intf]; !ok {
			_, err := e.c.IngressNodeFwAttach([]string{intf}, true)
			if err != nil {
				return err
			}
		}
		// TODO: Clean up all rules that were associated to this interface - somehow part of e.c.'s functionality?
	}

	// Add rules for both managed and unmanaged interfaces given that the add operation is already idempotent.
	// TODO missing functionality to purge undesired rules - should be part of e.c's functionality?
	// Diff both the provided and the currently known IngressNodeFirewallRules interfaces.
	// Iterate over the current known IngressNodeFirewallRules and purge anything that should not be there.
	for intf, ingress := range ifaceIngressRules {
		if _, ok := e.managedInterfaces[intf]; !ok {
			// Attach to the interfaces.
			logger.Info("Attaching firewall interface", "intf", intf)
			_, err := e.c.IngressNodeFwAttach([]string{intf}, isDelete)
			if err != nil {
				logger.Error(err, "Fail to attach ingress firewall prog")
				return err
			}
			e.managedInterfaces[intf] = struct{}{}
		}

		// Look up the network interface by name.
		iface, err := net.InterfaceByName(intf)
		if err != nil {
			return fmt.Errorf("lookup error for network iface %q: %s", intf, err)
		}
		ifId := uint32(iface.Index)

		// Add rules (TODO: should also purge undesired rules somehow).
		for _, rule := range ingress {
			rule := rule.DeepCopy()
			if err := addFailSaferules(&rule.FirewallProtocolRules); err != nil {
				logger.Error(err, "Fail to load ingress firewall fail safe rules", "rule", rule)
				return err
			}
			logger.Info("Loading rule", "intf", intf, "rule", rule)
			if err := e.c.IngressNodeFwRulesLoader(*rule, false, ifId); err != nil {
				logger.Error(err, "Failed loading ingress firewall rule", "intf", intf, "rule", rule)
				return err
			}
		}
	}

	return nil
}

// addFailSaferules appends failSafe rules to user configured one
func addFailSaferules(rules *[]infv1alpha1.IngressNodeFirewallProtocolRule) error {
	if rules == nil {
		return fmt.Errorf("invalid rules")
	}
	fsRuleIndex := failsaferules.MAX_INGRESS_RULES
	// Add TCP failsafe rules
	tcpFailSafeRules := failsaferules.GetTCP()
	for _, rule := range tcpFailSafeRules {
		rule := rule
		fsRule := infv1alpha1.IngressNodeFirewallProtocolRule{}
		fsRule.ProtocolConfig.TCP = new(infv1alpha1.IngressNodeFirewallProtoRule)
		fsRule.Order = uint32(fsRuleIndex)
		fsRuleIndex += 1
		fsRule.ProtocolConfig.Protocol = infv1alpha1.ProtocolTypeTCP
		(*fsRule.ProtocolConfig.TCP).Ports = intstr.FromInt(int(rule.GetPort()))
		fsRule.Action = infv1alpha1.IngressNodeFirewallAllow
		*rules = append(*rules, fsRule)
	}
	// Add UDP failsafe rules
	udpFailSafeRules := failsaferules.GetUDP()
	for _, rule := range udpFailSafeRules {
		rule := rule
		fsRule := infv1alpha1.IngressNodeFirewallProtocolRule{}
		fsRule.ProtocolConfig.UDP = new(infv1alpha1.IngressNodeFirewallProtoRule)
		fsRule.Order = uint32(fsRuleIndex)
		fsRuleIndex += 1
		fsRule.ProtocolConfig.Protocol = infv1alpha1.ProtocolTypeUDP
		(*fsRule.ProtocolConfig.UDP).Ports = intstr.FromInt(int(rule.GetPort()))
		fsRule.Action = infv1alpha1.IngressNodeFirewallAllow
		*rules = append(*rules, fsRule)
	}
	return nil
}
