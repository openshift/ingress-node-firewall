package tests

import (
	"context"
	"fmt"
	"os"

	"github.com/openshift/ingress-node-firewall/test/consts"
	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
	"github.com/openshift/ingress-node-firewall/test/e2e/ingress-node-firewall"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	goclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var OperatorNameSpace = consts.DefaultOperatorNameSpace

func init() {
	if ns := os.Getenv("OO_INSTALL_NAMESPACE"); len(ns) != 0 {
		OperatorNameSpace = ns
	}
}

var _ = Describe("IngressNodeFirewall", func() {
	Context("IngressNodeFirewall", func() {
		It("should have the IngressNodeFirewall Operator deployment in running state", func() {
			Eventually(func() bool {
				deploy, err := testclient.Client.Deployments(OperatorNameSpace).Get(context.Background(), consts.IngressNodeFirewallOperatorDeploymentName, metav1.GetOptions{})
				if err != nil {
					return false
				}
				return deploy.Status.ReadyReplicas == deploy.Status.Replicas
			}, ingressnodefirewall.DeployTimeout, ingressnodefirewall.Interval).Should(BeTrue())

			pods, err := testclient.Client.Pods(OperatorNameSpace).List(context.Background(), metav1.ListOptions{
				LabelSelector: fmt.Sprintf("control-plane=%s", consts.IngressNodeFirewallOperatorDeploymentLabel)})
			Expect(err).ToNot(HaveOccurred())

			deploy, err := testclient.Client.Deployments(OperatorNameSpace).Get(context.Background(), consts.IngressNodeFirewallOperatorDeploymentName, metav1.GetOptions{})
			Expect(err).ToNot(HaveOccurred())
			Expect(len(pods.Items)).To(Equal(int(deploy.Status.Replicas)))

			for _, pod := range pods.Items {
				Expect(pod.Status.Phase).To(Equal(corev1.PodRunning))
			}
		})

		It("should have the IngressNodeFirewallConfig CRD available in the cluster", func() {
			crd := &apiext.CustomResourceDefinition{}
			err := testclient.Client.Get(context.Background(), goclient.ObjectKey{Name: consts.IngressNodeFirewallConfigCRDName}, crd)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should have the IngressNodeFirewall CRD available in the cluster", func() {
			crd := &apiext.CustomResourceDefinition{}
			err := testclient.Client.Get(context.Background(), goclient.ObjectKey{Name: consts.IngressNodeFirewallRulesCRDName}, crd)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should have the IngressNodeFirewallNodeState CRD available in the cluster", func() {
			crd := &apiext.CustomResourceDefinition{}
			err := testclient.Client.Get(context.Background(), goclient.ObjectKey{Name: consts.IngressNodeFirewallNodeStateCRDName}, crd)
			Expect(err).ToNot(HaveOccurred())
		})
	})
})
