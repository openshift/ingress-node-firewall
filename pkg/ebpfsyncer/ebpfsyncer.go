package ebpfsyncer

import (
	"context"
	"fmt"
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
			c, err := nodefwloader.NewIngNodeFwController()
			if err != nil {
				panic(fmt.Errorf("Fail to create nodefw controller instance, err: %q", err))
			}

			instance = &ebpfSingleton{
				ctx:   ctx,
				log:   log,
				stats: stats,
				c:     c,
			}
		} else {
			instance = mock
		}
	})
	return instance
}

// ebpfSingleton implements ebpfDaemon.
type ebpfSingleton struct {
	ctx   context.Context
	log   logr.Logger
	stats *metrics.Statistics
	c     *nodefwloader.IngNodeFwController
}

// syncInterfaceIngressRules takes a map of <interfaceName>:<interfaceRules> and a boolean parameter that indicates
// if rules shall be attached to the interface or if rules shall be detached from the interface.
// If isDelete is true then all rules will be attached from all provided interfaces. In such a case, the given
// intefaceRules (if any) will be ignored.
// If isDelete is false then rules will be synchronized for each of the given interfaces.
func (e *ebpfSingleton) SyncInterfaceIngressRules(
	ifaceIngressRules map[string][]infv1alpha1.IngressNodeFirewallRules, isDelete bool) error {

	logger := e.log.WithName("syncIngressNodeFirewallResources")
	logger.Info("Start")

	if e.stats != nil {
		e.stats.StopPoll()
	}

	for intf, ingress := range ifaceIngressRules {
		ifMap, err := e.c.IngressNodeFwAttach([]string{intf}, isDelete)
		if err != nil {
			logger.Error(err, "Fail to attach ingress firewall prog")
			return err
		}
		for _, rule := range ingress {
			rule := rule.DeepCopy()
			if err := addFailSaferules(&rule.FirewallProtocolRules); err != nil {
				logger.Error(err, "Fail to load ingress firewall fail safe rules", "rule", rule)
				return err
			}
			ifId, ok := ifMap[intf]
			if !ok {
				return fmt.Errorf("interface %s not found in attached interface list", intf)
			}
			if err := e.c.IngressNodeFwRulesLoader(*rule, isDelete, ifId); err != nil {
				logger.Error(err, "Fail to load ingress firewall rule", "rule", rule)
				return err
			}
		}
	}

	if e.stats != nil {
		e.stats.StartPoll(e.c.GetStatisticsMap())
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
