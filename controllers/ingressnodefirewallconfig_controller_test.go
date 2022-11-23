package controllers

import (
	"context"
	"fmt"
	"time"

	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("Ingress nodefirewall config Controller", func() {
	Context("syncIngressNodeFwConfig", func() {
		It("Should create manifests with images and namespace overridden", func() {

			config := &ingressnodefwv1alpha1.IngressNodeFirewallConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      IngressNodeFirewallResourceName,
					Namespace: IngressNodeFwConfigTestNameSpace,
				},
			}
			daemonContainers := map[string]string{
				"daemon":          "test-daemon:latest",
				"events":          "test-daemon:latest",
				"kube-rbac-proxy": "kube-rbac-proxy:latest",
			}

			By("Creating a Ingress node firewall config resource")
			err := k8sClient.Create(context.Background(), config)
			Expect(err).ToNot(HaveOccurred())

			By("Validating that the daemonset variables were templated correctly")
			daemonSet := &appsv1.DaemonSet{}
			Eventually(func() error {
				err := k8sClient.Get(context.Background(), types.NamespacedName{Name: DeamonSetName, Namespace: IngressNodeFwConfigTestNameSpace}, daemonSet)
				return err
			}, 2*time.Second, 200*time.Millisecond).ShouldNot((HaveOccurred()))
			Expect(daemonSet).NotTo(BeZero())
			Expect(daemonSet.Spec.Template.Spec.Containers).To(HaveLen(len(daemonContainers)))
			for _, c := range daemonSet.Spec.Template.Spec.Containers {
				image, ok := daemonContainers[c.Name]
				Expect(ok).To(BeTrue(), fmt.Sprintf("container %s not found in %s", c.Name, daemonContainers))
				Expect(c.Image).To(Equal(image))
			}

			config = &ingressnodefwv1alpha1.IngressNodeFirewallConfig{}
			err = k8sClient.Get(context.Background(), types.NamespacedName{Name: IngressNodeFirewallResourceName, Namespace: IngressNodeFwConfigTestNameSpace}, config)
			Expect(err).NotTo(HaveOccurred())
			By("Specify the NodeSelector")
			config.Spec.NodeSelector = map[string]string{"node-role.kubernetes.io/worker": "true"}
			err = k8sClient.Update(context.TODO(), config)
			Expect(err).NotTo(HaveOccurred())
			daemonSet = &appsv1.DaemonSet{}
			Eventually(func() map[string]string {
				err := k8sClient.Get(context.TODO(), types.NamespacedName{Name: DeamonSetName, Namespace: IngressNodeFwConfigTestNameSpace}, daemonSet)
				if err != nil {
					return nil
				}
				return daemonSet.Spec.Template.Spec.NodeSelector
			}, 2*time.Second, 200*time.Millisecond).Should(Equal(config.Spec.NodeSelector))
			Expect(daemonSet).NotTo(BeZero())
			Expect(len(daemonSet.Spec.Template.Spec.Containers)).To(BeNumerically(">", 0))
			// Reset nodeSelector configuration
			config = &ingressnodefwv1alpha1.IngressNodeFirewallConfig{}
			err = k8sClient.Get(context.Background(), types.NamespacedName{Name: IngressNodeFirewallResourceName, Namespace: IngressNodeFwConfigTestNameSpace}, config)
			Expect(err).NotTo(HaveOccurred())
			config.Spec.NodeSelector = map[string]string{}
			err = k8sClient.Update(context.TODO(), config)
			Expect(err).NotTo(HaveOccurred())

			config = &ingressnodefwv1alpha1.IngressNodeFirewallConfig{}
			err = k8sClient.Get(context.Background(), types.NamespacedName{Name: IngressNodeFirewallResourceName, Namespace: IngressNodeFwConfigTestNameSpace}, config)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
