package ingressnodefirewall

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"time"

	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	"github.com/openshift/ingress-node-firewall/test/consts"
	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"

	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/util/yaml"
	goclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Timeout and Interval settings
	Timeout       = time.Second * 40
	DeployTimeout = time.Minute * 3
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

func NodesIP(nodes []v1.Node) []string {
	res := []string{}
	for _, n := range nodes {
		for _, a := range n.Status.Addresses {
			if a.Type == v1.NodeInternalIP {
				res = append(res, a.Address)
			}
		}
	}
	return res
}

func RunPingTest(nodes []v1.Node) (error, int) {
	var errs []error
	ii := NodesIP(nodes)
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

func GetINF(operatorNamespace string) *ingressnodefwv1alpha1.IngressNodeFirewall {
	inf := &ingressnodefwv1alpha1.IngressNodeFirewall{}
	inf.SetName("e2e-test")
	inf.SetNamespace(operatorNamespace)
	return inf
}

func DefineWithWorkerNodeSelector(inf *ingressnodefwv1alpha1.IngressNodeFirewall) {
	inf.Spec.NodeSelector = map[string]string{
		"node-role.kubernetes.io/worker": "",
	}
}

func DefineWithInterface(inf *ingressnodefwv1alpha1.IngressNodeFirewall, interfaceName string) {
	inf.Spec.Interfaces = &[]string{
		interfaceName,
	}
}

func DefineDenyTCPRule(inf *ingressnodefwv1alpha1.IngressNodeFirewall, sourceCIDR string, port uint16) {
	inf.Spec.Ingress = append(inf.Spec.Ingress, ingressnodefwv1alpha1.IngressNodeFirewallRules{
		SourceCIDRs: []string{sourceCIDR},
		FirewallProtocolRules: []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
			{
				Order: 1,
				ProtocolRule: &ingressnodefwv1alpha1.IngressNodeFirewallProtoRule{
					Ports: strconv.Itoa(int(port)),
				},
				Protocol: ingressnodefwv1alpha1.ProtocolTypeTCP,
				Action:   ingressnodefwv1alpha1.IngressNodeFirewallDeny,
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
				ProtocolRule: &ingressnodefwv1alpha1.IngressNodeFirewallProtoRule{
					Ports: strconv.Itoa(int(port)),
				},
				Protocol: ingressnodefwv1alpha1.ProtocolTypeUDP,
				Action:   ingressnodefwv1alpha1.IngressNodeFirewallDeny,
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
				ICMPRule: &ingressnodefwv1alpha1.IngressNodeFirewallICMPRule{
					ICMPCode: 8,
				},
				Protocol: ingressnodefwv1alpha1.ProtocolTypeICMP,
				Action:   ingressnodefwv1alpha1.IngressNodeFirewallDeny,
			},
		},
	})
}
