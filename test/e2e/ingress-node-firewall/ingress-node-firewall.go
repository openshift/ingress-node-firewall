package ingressnodefirewall

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	"github.com/openshift/ingress-node-firewall/test/consts"
	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/yaml"
	goclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// DeleteIngressNodeFirewallConfig and check the IngressNodeFirewallConfig custom resource is deleted to avoid status leak in between tests.
func DeleteIngressNodeFirewallConfig(client *testclient.ClientSet, config *ingressnodefwv1alpha1.IngressNodeFirewallConfig, interval, timeout time.Duration) {
	err := client.Delete(context.Background(), config)
	if errors.IsNotFound(err) { // Ignore err, could be already deleted.
		return
	}
	Expect(err).ToNot(HaveOccurred())

	Eventually(func() bool {
		err := client.Get(context.Background(), goclient.ObjectKey{Namespace: config.Namespace, Name: config.Name}, config)
		return errors.IsNotFound(err)
	}, timeout, interval).Should(BeTrue(), "Failed to delete IngressNodeFirewallConfig custom resource")

	Eventually(func() bool {
		_, err := client.DaemonSets(config.Namespace).Get(context.Background(), consts.IngressNodeFirewallDaemonsetName, metav1.GetOptions{})
		return errors.IsNotFound(err)
	}, timeout, interval).Should(BeTrue())

	Eventually(func() bool {
		pods, _ := client.Pods(consts.DefaultOperatorNameSpace).List(context.Background(), metav1.ListOptions{
			LabelSelector: fmt.Sprintf("component=%s", consts.IngressNodeFirewallDaemonsetName)})
		return len(pods.Items) == 0
	}, timeout, interval).Should(BeTrue())
}

func LoadIngressNodeFirewallConfigFromFile(config *ingressnodefwv1alpha1.IngressNodeFirewallConfig, fileName string) error {
	return loadFromFile(config, fileName)
}

func loadFromFile(obj interface{}, fileName string) error {
	f, err := os.Open(fmt.Sprintf("../../../config/samples/%s", fileName))
	if err != nil {
		return err
	}
	defer f.Close()

	return decodeYAML(f, obj)
}

func decodeYAML(r io.Reader, obj interface{}) error {
	decoder := yaml.NewYAMLToJSONDecoder(r)
	return decoder.Decode(obj)
}

func EnsureIngressNodeFirewallConfigExists(client *testclient.ClientSet, config *ingressnodefwv1alpha1.IngressNodeFirewallConfig,
	timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := client.Create(ctx, config)
	if err != nil {
		if errors.IsAlreadyExists(err) {
			return nil
		}
	}
	return err
}

func CreateIngressNodeFirewall(client *testclient.ClientSet, inf *ingressnodefwv1alpha1.IngressNodeFirewall,
	timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// we want to return failure if it already exists to avoid leaks between test cases.
	return client.Create(ctx, inf)
}

func DeleteIngressNodeFirewall(client *testclient.ClientSet, inf *ingressnodefwv1alpha1.IngressNodeFirewall,
	timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// we want to return failure if it already deleted to highlight possible test setup failure.
	return client.Delete(ctx, inf)
}

func DeleteIngressNodeFirewallsWithLabels(client *testclient.ClientSet, namespace, label string, timeout time.Duration) error {
	var infList ingressnodefwv1alpha1.IngressNodeFirewallList
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := client.List(ctx, &infList, goclient.InNamespace(namespace), &goclient.HasLabels{label})
	if err != nil {
		return err
	}
	for _, inf := range infList.Items {
		if err = DeleteIngressNodeFirewall(client, &inf, timeout); err != nil {
			if !errors.IsNotFound(err) {
				return err
			}
		}
	}
	return nil
}

func DefineWithWorkerNodeSelector(inf *ingressnodefwv1alpha1.IngressNodeFirewall) {
	inf.Spec.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{consts.IngressNodeFirewallNodeLabel: ""},
	}
}

func DefineWithInterface(inf *ingressnodefwv1alpha1.IngressNodeFirewall, interfaceName string) {
	inf.Spec.Interfaces = []string{
		interfaceName,
	}
}

func DefineWithInterfaces(inf *ingressnodefwv1alpha1.IngressNodeFirewall, interfaces []string) {
	inf.Spec.Interfaces = interfaces
}

func AppendIngress(inf *ingressnodefwv1alpha1.IngressNodeFirewall, sourceCIDR string, rules ...ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule) {
	inf.Spec.Ingress = append(inf.Spec.Ingress, ingressnodefwv1alpha1.IngressNodeFirewallRules{
		SourceCIDRs:           []string{sourceCIDR},
		FirewallProtocolRules: rules,
	})
}

func GetTCPRule(order uint32, port string, action ingressnodefwv1alpha1.IngressNodeFirewallActionType) ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule {
	return ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
		Order: order,
		ProtocolConfig: ingressnodefwv1alpha1.IngressNodeProtocolConfig{
			Protocol: ingressnodefwv1alpha1.ProtocolTypeTCP,
			TCP: &ingressnodefwv1alpha1.IngressNodeFirewallProtoRule{
				Ports: intstr.FromString(port),
			},
		},
		Action: action,
	}
}

func GetUDPRule(order uint32, port string, action ingressnodefwv1alpha1.IngressNodeFirewallActionType) ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule {
	return ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
		Order: order,
		ProtocolConfig: ingressnodefwv1alpha1.IngressNodeProtocolConfig{
			Protocol: ingressnodefwv1alpha1.ProtocolTypeUDP,
			UDP: &ingressnodefwv1alpha1.IngressNodeFirewallProtoRule{
				Ports: intstr.FromString(port),
			},
		},
		Action: action,
	}
}

func GetSCTPRule(order uint32, port string, action ingressnodefwv1alpha1.IngressNodeFirewallActionType) ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule {
	return ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
		Order: order,
		ProtocolConfig: ingressnodefwv1alpha1.IngressNodeProtocolConfig{
			Protocol: ingressnodefwv1alpha1.ProtocolTypeSCTP,
			SCTP: &ingressnodefwv1alpha1.IngressNodeFirewallProtoRule{
				Ports: intstr.FromString(port),
			},
		},
		Action: action,
	}
}

func GetICMPV4Rule(order uint32, icmpType, icmpCode uint8, action ingressnodefwv1alpha1.IngressNodeFirewallActionType) ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule {
	return ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
		Order: order,
		ProtocolConfig: ingressnodefwv1alpha1.IngressNodeProtocolConfig{
			Protocol: ingressnodefwv1alpha1.ProtocolTypeICMP,
			ICMP: &ingressnodefwv1alpha1.IngressNodeFirewallICMPRule{
				ICMPType: icmpType,
				ICMPCode: icmpCode,
			},
		},
		Action: action,
	}
}

func GetTransportProtocolBlockPortRule(proto ingressnodefwv1alpha1.IngressNodeFirewallRuleProtocolType, order uint32, port string) ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule {
	switch proto {
	case ingressnodefwv1alpha1.ProtocolTypeTCP:
		return GetTCPRule(order, port, ingressnodefwv1alpha1.IngressNodeFirewallDeny)
	case ingressnodefwv1alpha1.ProtocolTypeUDP:
		return GetUDPRule(order, port, ingressnodefwv1alpha1.IngressNodeFirewallDeny)
	case ingressnodefwv1alpha1.ProtocolTypeSCTP:
		return GetSCTPRule(order, port, ingressnodefwv1alpha1.IngressNodeFirewallDeny)
	default:
		panic("Unsupported protocol")
	}
}

func GetICMPBlockRule(proto ingressnodefwv1alpha1.IngressNodeFirewallRuleProtocolType, order uint32, icmpType, icmpCode uint8) ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule {
	switch proto {
	case ingressnodefwv1alpha1.ProtocolTypeICMP:
		return ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
			Order: order,
			ProtocolConfig: ingressnodefwv1alpha1.IngressNodeProtocolConfig{
				Protocol: proto,
				ICMP: &ingressnodefwv1alpha1.IngressNodeFirewallICMPRule{
					ICMPType: icmpType,
					ICMPCode: icmpCode,
				},
			},
			Action: ingressnodefwv1alpha1.IngressNodeFirewallDeny,
		}
	case ingressnodefwv1alpha1.ProtocolTypeICMP6:
		return ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
			Order: order,
			ProtocolConfig: ingressnodefwv1alpha1.IngressNodeProtocolConfig{
				Protocol: proto,
				ICMPv6: &ingressnodefwv1alpha1.IngressNodeFirewallICMPRule{
					ICMPType: icmpType,
					ICMPCode: icmpCode,
				},
			},
			Action: ingressnodefwv1alpha1.IngressNodeFirewallDeny,
		}
	default:
		panic("Unsupported protocol")
	}
}

func IsTransportProtocol(protocol ingressnodefwv1alpha1.IngressNodeFirewallRuleProtocolType) bool {
	if protocol == ingressnodefwv1alpha1.ProtocolTypeTCP || protocol == ingressnodefwv1alpha1.ProtocolTypeUDP ||
		protocol == ingressnodefwv1alpha1.ProtocolTypeSCTP {
		return true
	}
	return false
}

func IsICMPProtocol(protocol ingressnodefwv1alpha1.IngressNodeFirewallRuleProtocolType) bool {
	if protocol == ingressnodefwv1alpha1.ProtocolTypeICMP || protocol == ingressnodefwv1alpha1.ProtocolTypeICMP6 {
		return true
	}
	return false
}
