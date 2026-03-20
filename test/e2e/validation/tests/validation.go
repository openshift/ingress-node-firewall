package tests

import (
	"context"
	"fmt"
	"os"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	"github.com/openshift/ingress-node-firewall/test/consts"
	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
	corev1 "k8s.io/api/core/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	goclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	operatorNameSpace = consts.DefaultOperatorNameSpace
	timeout           = 40 * time.Second
	retryInterval     = 10 * time.Millisecond
)

func init() {
	if ns := os.Getenv("OO_INSTALL_NAMESPACE"); len(ns) != 0 {
		operatorNameSpace = ns
	}
}

var _ = ginkgo.Describe("IngressNodeFirewall", func() {
	ginkgo.Context("IngressNodeFirewall", func() {
		ginkgo.It("should have the IngressNodeFirewall Operator deployment in running state", func() {
			gomega.Eventually(func() bool {
				deploy, err := testclient.Client.Deployments(operatorNameSpace).Get(context.Background(), consts.IngressNodeFirewallOperatorDeploymentName, metav1.GetOptions{})
				if err != nil {
					return false
				}
				return deploy.Status.ReadyReplicas == deploy.Status.Replicas
			}, timeout, retryInterval).Should(gomega.BeTrue())

			pods, err := testclient.Client.Pods(operatorNameSpace).List(context.Background(), metav1.ListOptions{
				LabelSelector: fmt.Sprintf("control-plane=%s", consts.IngressNodeFirewallOperatorDeploymentLabel)})
			gomega.Expect(err).ToNot(gomega.HaveOccurred())

			deploy, err := testclient.Client.Deployments(operatorNameSpace).Get(context.Background(), consts.IngressNodeFirewallOperatorDeploymentName, metav1.GetOptions{})
			gomega.Expect(err).ToNot(gomega.HaveOccurred())
			gomega.Expect(len(pods.Items)).To(gomega.Equal(int(deploy.Status.Replicas)))

			for _, pod := range pods.Items {
				gomega.Expect(pod.Status.Phase).To(gomega.Equal(corev1.PodRunning))
			}
		})

		ginkgo.It("should have the IngressNodeFirewallConfig CRD available in the cluster", func() {
			crd := &apiext.CustomResourceDefinition{}
			err := testclient.Client.Get(context.Background(), goclient.ObjectKey{Name: consts.IngressNodeFirewallConfigCRDName}, crd)
			gomega.Expect(err).ToNot(gomega.HaveOccurred())
		})

		ginkgo.It("should have the IngressNodeFirewall CRD available in the cluster", func() {
			crd := &apiext.CustomResourceDefinition{}
			err := testclient.Client.Get(context.Background(), goclient.ObjectKey{Name: consts.IngressNodeFirewallRulesCRDName}, crd)
			gomega.Expect(err).ToNot(gomega.HaveOccurred())
		})

		ginkgo.It("should have the IngressNodeFirewallNodeState CRD available in the cluster", func() {
			crd := &apiext.CustomResourceDefinition{}
			err := testclient.Client.Get(context.Background(), goclient.ObjectKey{Name: consts.IngressNodeFirewallNodeStateCRDName}, crd)
			gomega.Expect(err).ToNot(gomega.HaveOccurred())
		})
	})
})
