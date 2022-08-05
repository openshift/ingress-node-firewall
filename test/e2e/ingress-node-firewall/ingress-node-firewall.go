package ingressnodefirewall

import (
	"context"
	"fmt"
	"io"
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

func Get(operatorNamespace string) (*ingressnodefwv1alpha1.IngressNodeFirewallConfig, error) {
	config := &ingressnodefwv1alpha1.IngressNodeFirewallConfig{}
	config.SetName("ingressnodefirewallconfig")
	config.SetNamespace(operatorNamespace)
	return config, nil
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
