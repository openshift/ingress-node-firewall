package ingressnodefirewall

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"

	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	"github.com/openshift/ingress-node-firewall/test/consts"
	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"

	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/util/yaml"
	goclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Timeout and Interval settings
	Timeout       = time.Second * 40
	DeployTimeout = time.Minute * 5
	Interval      = time.Second * 4
)

// DeleteINFConfig and check the IngressNodeFirewallConfig custom resource is deleted to avoid status leak in between tests.
func DeleteINFConfig(config *ingressnodefwv1alpha1.IngressNodeFirewallConfig) {
	err := testclient.Client.Delete(context.Background(), config)
	if errors.IsNotFound(err) { // Ignore err, could be already deleted.
		return
	}
	Expect(err).ToNot(HaveOccurred())

	Eventually(func() bool {
		err := testclient.Client.Get(context.Background(), goclient.ObjectKey{Namespace: config.Namespace, Name: config.Name}, config)
		return errors.IsNotFound(err)
	}, 1*time.Minute, 5*time.Second).Should(BeTrue(), "Failed to delete IngressNodeFirewallConfig custom resource")

	Eventually(func() bool {
		_, err := testclient.Client.DaemonSets(config.Namespace).Get(context.Background(), consts.IngressNodeFirewallDaemonsetName, metav1.GetOptions{})
		return errors.IsNotFound(err)
	}, DeployTimeout, Interval).Should(BeTrue())

	Eventually(func() bool {
		pods, _ := testclient.Client.Pods(consts.DefaultOperatorNameSpace).List(context.Background(), metav1.ListOptions{
			LabelSelector: fmt.Sprintf("component=%s", consts.IngressNodeFirewallDaemonsetName)})
		return len(pods.Items) == 0
	}, DeployTimeout, Interval).Should(BeTrue())
}

func decodeYAML(r io.Reader, obj interface{}) error {
	decoder := yaml.NewYAMLToJSONDecoder(r)
	return decoder.Decode(obj)
}

func LoadIngressNodeFirewallConfigFromFile(config *ingressnodefwv1alpha1.IngressNodeFirewallConfig, fileName string) error {
	return loadFromFile(config, fileName)
}

func LoadIngressNodeFirewallFromFile(inf *ingressnodefwv1alpha1.IngressNodeFirewall, fileName string) error {
	return loadFromFile(inf, fileName)
}

func loadFromFile(obj interface{}, fileName string) error {
	f, err := os.Open(fmt.Sprintf("../../../config/samples/%s", fileName))
	if err != nil {
		return err
	}
	defer f.Close()

	return decodeYAML(f, obj)
}

func NodeIPs(nodeName string) ([]string, error) {
	var res []string

	node, err := testclient.Client.Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	for _, a := range node.Status.Addresses {
		if a.Type == v1.NodeInternalIP {
			res = append(res, a.Address)
		}
	}
	return res, nil
}

func NodesIPs(nodes []v1.Node) []string {
	var res []string
	for _, n := range nodes {
		for _, a := range n.Status.Addresses {
			if a.Type == v1.NodeInternalIP {
				res = append(res, a.Address)
			}
		}
	}
	return res
}

func GetRuleCIDR(nodes []v1.Node) (string, string, error) {
	var v4CIDR, v6CIDR string
	v4CIDRLen := 12
	v6CIDRLen := 64
	ips := NodesIPs(nodes)
	for _, ip := range ips {
		addr := net.ParseIP(ip)
		if addr.To4() != nil {
			v4Mask := net.CIDRMask(v4CIDRLen, 32)
			v4CIDR = fmt.Sprintf("%s/%d", addr.Mask(v4Mask), v4CIDRLen)
		} else if addr.To16() != nil {
			v6Mask := net.CIDRMask(v6CIDRLen, 128)
			v6CIDR = fmt.Sprintf("%s/%d", addr.Mask(v6Mask), v6CIDRLen)
		} else {
			return "", "", fmt.Errorf("invalid ip address family %s", ip)
		}
		if v4CIDR != "" && v6CIDR != "" {
			break
		}
	}
	return v4CIDR, v6CIDR, nil
}

func RunPingTest(nodes []v1.Node) (error, int) {
	var errs []error
	ii := NodesIPs(nodes)
	for _, ip := range ii {
		if _, err := exec.Command("ping", "-c", "1", ip).CombinedOutput(); err != nil {
			errs = append(errs, err)
		}
	}
	return kerrors.NewAggregate(errs), len(errs)
}

func GetDaemonSetPods(ns string) (*v1.PodList, error) {
	var podList *v1.PodList
	err := wait.PollImmediate(1*time.Second, 10*time.Second, func() (done bool, err error) {
		podList, err = testclient.Client.Pods(ns).List(context.TODO(), metav1.ListOptions{
			LabelSelector: "app=ingress-node-firewall-daemon",
		})

		if err != nil {
			return false, err
		}

		if len(podList.Items) > 0 {
			return true, nil
		}
		return false, nil
	})
	return podList, err
}

func GetINF(operatorNamespace string, name string) *ingressnodefwv1alpha1.IngressNodeFirewall {
	inf := &ingressnodefwv1alpha1.IngressNodeFirewall{}
	inf.SetName(name)
	inf.SetNamespace(operatorNamespace)
	return inf
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

func DefineDenyTCPRule(inf *ingressnodefwv1alpha1.IngressNodeFirewall, sourceCIDR string, port uint16) {
	inf.Spec.Ingress = append(inf.Spec.Ingress, ingressnodefwv1alpha1.IngressNodeFirewallRules{
		SourceCIDRs: []string{sourceCIDR},
		FirewallProtocolRules: []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
			{
				Order: 1,
				ProtocolConfig: ingressnodefwv1alpha1.IngressNodeProtocolConfig{
					Protocol: ingressnodefwv1alpha1.ProtocolTypeTCP,
					TCP: &ingressnodefwv1alpha1.IngressNodeFirewallProtoRule{
						Ports: intstr.FromInt(int(port)),
					},
				},
				Action: ingressnodefwv1alpha1.IngressNodeFirewallDeny,
			},
		},
	})
}

func DefineDenyUDPRule(inf *ingressnodefwv1alpha1.IngressNodeFirewall, sourceCIDR string, port uint16) {
	inf.Spec.Ingress = append(inf.Spec.Ingress, ingressnodefwv1alpha1.IngressNodeFirewallRules{
		SourceCIDRs: []string{sourceCIDR},
		FirewallProtocolRules: []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
			{
				Order: 1,
				ProtocolConfig: ingressnodefwv1alpha1.IngressNodeProtocolConfig{
					Protocol: ingressnodefwv1alpha1.ProtocolTypeUDP,
					UDP: &ingressnodefwv1alpha1.IngressNodeFirewallProtoRule{
						Ports: intstr.FromInt(int(port)),
					},
				},
				Action: ingressnodefwv1alpha1.IngressNodeFirewallDeny,
			},
		},
	})
}

func DefineDenySCTPRule(inf *ingressnodefwv1alpha1.IngressNodeFirewall, sourceCIDR string, port uint16) {
	inf.Spec.Ingress = append(inf.Spec.Ingress, ingressnodefwv1alpha1.IngressNodeFirewallRules{
		SourceCIDRs: []string{sourceCIDR},
		FirewallProtocolRules: []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
			{
				Order: 1,
				ProtocolConfig: ingressnodefwv1alpha1.IngressNodeProtocolConfig{
					Protocol: ingressnodefwv1alpha1.ProtocolTypeSCTP,
					SCTP: &ingressnodefwv1alpha1.IngressNodeFirewallProtoRule{
						Ports: intstr.FromInt(int(port)),
					},
				},
				Action: ingressnodefwv1alpha1.IngressNodeFirewallDeny,
			},
		},
	})
}

func DefineDenyICMPV4Rule(inf *ingressnodefwv1alpha1.IngressNodeFirewall, sourceCIDR string) {
	inf.Spec.Ingress = append(inf.Spec.Ingress, ingressnodefwv1alpha1.IngressNodeFirewallRules{
		SourceCIDRs: []string{sourceCIDR},
		FirewallProtocolRules: []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
			{
				Order: 1,
				ProtocolConfig: ingressnodefwv1alpha1.IngressNodeProtocolConfig{
					Protocol: ingressnodefwv1alpha1.ProtocolTypeICMP,
					ICMP: &ingressnodefwv1alpha1.IngressNodeFirewallICMPRule{
						ICMPCode: 8,
					},
				},
				Action: ingressnodefwv1alpha1.IngressNodeFirewallDeny,
			},
		},
	})
}

func DefineDenyICMPV6Rule(inf *ingressnodefwv1alpha1.IngressNodeFirewall, sourceCIDR string) {
	inf.Spec.Ingress = append(inf.Spec.Ingress, ingressnodefwv1alpha1.IngressNodeFirewallRules{
		SourceCIDRs: []string{sourceCIDR},
		FirewallProtocolRules: []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
			{
				Order: 1,
				ProtocolConfig: ingressnodefwv1alpha1.IngressNodeProtocolConfig{
					Protocol: ingressnodefwv1alpha1.ProtocolTypeICMP6,
					ICMPv6: &ingressnodefwv1alpha1.IngressNodeFirewallICMPRule{
						ICMPCode: 8,
					},
				},
				Action: ingressnodefwv1alpha1.IngressNodeFirewallDeny,
			},
		},
	})
}

// GetPodLogs returns the logs from container, or an error if the logs
// could not be fetched.
func GetPodLogs(clientset *testclient.ClientSet, pod *v1.Pod, container string) (string, error) {
	req := clientset.Pods(pod.Namespace).GetLogs(pod.Name, &v1.PodLogOptions{Container: container})
	logStream, err := req.Stream(context.Background())
	if err != nil {
		return "", err
	}
	defer logStream.Close()
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, logStream); err != nil {
		return "", err
	}
	return buf.String(), nil
}
