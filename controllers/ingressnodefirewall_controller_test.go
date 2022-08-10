package controllers

import (
	"context"
	"fmt"
	"time"

	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("IngressNodeFirewall controller", func() {

	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	ctx := context.Background()

	ingressNodeFirewallName := "firewall1"
	rules := []infv1alpha1.IngressNodeFirewallRules{
		{
			SourceCIDRs: []string{"10.0.0.0"},
			FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
				{
					Order: 10,
					ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
						Protocol: infv1alpha1.ProtocolTypeTCP,
						TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
							Ports: intstr.FromInt(80),
						},
					},
					Action: infv1alpha1.IngressNodeFirewallAllow,
				},
			},
		},
	}
	interfaces := []string{"eth0"}

	BeforeEach(func() {
		nodes := []v1.Node{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "control-plane-0",
					Labels: map[string]string{
						"node-role.kubernetes.io/control-plane": "",
					},
				},
			}, {
				ObjectMeta: metav1.ObjectMeta{
					Name: "worker-0",
					Labels: map[string]string{
						"node-role.kubernetes.io/worker": "",
						"ingress-node-firewall":          "enabled",
					},
				},
			}, {
				ObjectMeta: metav1.ObjectMeta{
					Name: "worker-1",
					Labels: map[string]string{
						"node-role.kubernetes.io/worker": "",
					},
				},
			},
		}
		for _, node := range nodes {
			By(fmt.Sprintf("By creating node %s", node.Name))
			Expect(k8sClient.Create(ctx, &node)).Should(Succeed())
		}

		By("By creating a new IngressNodeFirewall object that matches the worker label")
		ingressNodeFirewall := infv1alpha1.IngressNodeFirewall{
			TypeMeta:   metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{Name: ingressNodeFirewallName},
			Spec: infv1alpha1.IngressNodeFirewallSpec{
				NodeSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"node-role.kubernetes.io/worker": ""},
				},
				Ingress:    rules,
				Interfaces: interfaces,
			},
			Status: infv1alpha1.IngressNodeFirewallStatus{},
		}

		Expect(k8sClient.Create(ctx, &ingressNodeFirewall)).Should(Succeed())
	})

	AfterEach(func() {
		Expect(k8sClient.DeleteAllOf(context.Background(), &infv1alpha1.IngressNodeFirewall{})).Should(Succeed())
		Expect(k8sClient.DeleteAllOf(context.Background(), &v1.Node{})).Should(Succeed())
		Expect(k8sClient.DeleteAllOf(
			context.Background(),
			&infv1alpha1.IngressNodeFirewallNodeState{},
			client.InNamespace(IngressNodeFwConfigTestNameSpace))).Should(Succeed())
	})

	// Baseline test.
	When("an IngressNodeFirewall object is created that matches all worker nodes", func() {
		It("All worker nodes should have a valid IngressNodeFirewallNodeState", func() {
			By("By checking that we have an IngressNodeFirewallNodeState object on every worker node")
			nodeStateList := &infv1alpha1.IngressNodeFirewallNodeStateList{}
			expectedNodeNames := []string{"worker-0", "worker-1"}
			Eventually(func() bool {
				err := k8sClient.List(ctx, nodeStateList, []client.ListOption{}...)
				if err != nil {
					fmt.Fprintf(GinkgoWriter, "Could not list IngressNodeFirewallNodeStates during this iteration\n")
					return false
				}
				// Check number of items.
				if len(nodeStateList.Items) != len(expectedNodeNames) {
					fmt.Fprintf(GinkgoWriter, "Could not find the desired number of IngressNodeFirewallNodeStates\n")
					return false
				}
				// Check item names.
				for _, name := range expectedNodeNames {
					nameMatches := false
					for _, nodeState := range nodeStateList.Items {
						if name == nodeState.Name {
							nameMatches = true
							break
						}
					}
					if !nameMatches {
						fmt.Fprintf(GinkgoWriter,
							"Did not find the expected IngressNodeFirewallNodeState with name %s\n", name)
						return false
					}
				}
				// Check item content.
				for _, nodeState := range nodeStateList.Items {
					if !equality.Semantic.DeepEqual(nodeState.Spec.Ingress, rules) {
						fmt.Fprintf(GinkgoWriter,
							"IngressNodeFirewallNodeState.Spec.Ingress does not match IngressNodeFirewall.Spec.Ingress "+
								"for object with name %s\n", nodeState.Name)
						return false
					}
					if len(nodeState.Spec.Interfaces) != 1 || (nodeState.Spec.Interfaces)[0] != "eth0" {
						fmt.Fprintf(GinkgoWriter,
							"IngressNodeFirewallNodeState.Spec.Interfaces does not match IngressNodeFirewall.Spec.Interfaces "+
								"for object with name %s\n", nodeState.Name)
						return false
					}
				}

				return true
			}, timeout, interval).Should(BeTrue())
		})
	})

	// Test updates to IngressNodeFirewalls.
	When("the nodeSelector is updated to match no node", func() {
		It("The IngressNodeFirewallNodeState objects should be deleted", func() {
			By("Waiting for the expected number of IngressNodeFirewallNodeStates")
			nodeStateList := &infv1alpha1.IngressNodeFirewallNodeStateList{}
			Eventually(func() bool {
				err := k8sClient.List(ctx, nodeStateList, []client.ListOption{}...)
				if err != nil {
					fmt.Fprintf(GinkgoWriter, "Could not list IngressNodeFirewallNodeStates during this iteration\n")
					return false
				}
				// Check number of items.
				if len(nodeStateList.Items) != 2 {
					fmt.Fprintf(GinkgoWriter, "Could not find the desired number of IngressNodeFirewallNodeStates\n")
					return false
				}
				return true
			})

			By(fmt.Sprintf("Updating the nodeSelector on IngressNodeFirewall %s", ingressNodeFirewallName))
			err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				inf := &infv1alpha1.IngressNodeFirewall{}
				key := types.NamespacedName{Name: ingressNodeFirewallName}
				Expect(k8sClient.Get(ctx, key, inf)).Should(Succeed())
				inf.Spec.NodeSelector = metav1.LabelSelector{
					MatchLabels: map[string]string{},
				}
				return k8sClient.Update(ctx, inf)
			})
			Expect(err).NotTo(HaveOccurred())
		})

		By("By checking that we have no IngressNodeFirewallNodeState objects")
		nodeStateList := &infv1alpha1.IngressNodeFirewallNodeStateList{}
		Eventually(func() bool {
			err := k8sClient.List(ctx, nodeStateList, []client.ListOption{}...)
			if err != nil {
				fmt.Fprintf(GinkgoWriter, "Could not list IngressNodeFirewallNodeStates during this iteration\n")
				return false
			}
			// Check number of items.
			return len(nodeStateList.Items) == 0
		})
	})

	// Test updates to node labels.
	When("the label on worker-1 is removed", func() {
		It("The IngressNodeFirewallNodeState object for worker-1 should be deleted", func() {
			nodeStateList := &infv1alpha1.IngressNodeFirewallNodeStateList{}
			By("Waiting for the expected number of IngressNodeFirewallNodeStates")
			Eventually(func() bool {
				err := k8sClient.List(ctx, nodeStateList, []client.ListOption{}...)
				if err != nil {
					fmt.Fprintf(GinkgoWriter, "Could not list IngressNodeFirewallNodeStates during this iteration\n")
					return false
				}
				// Check number of items.
				if len(nodeStateList.Items) != 2 {
					fmt.Fprintf(GinkgoWriter, "Could not find the desired number of IngressNodeFirewallNodeStates\n")
					return false
				}
				return true
			})

			By(fmt.Sprintf("Updating the label on node worker-1"))
			err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				node := &v1.Node{}
				key := types.NamespacedName{Name: "worker-1"}
				Expect(k8sClient.Get(ctx, key, node)).Should(Succeed())
				node.Labels = map[string]string{}
				return k8sClient.Update(ctx, node)
			})
			Expect(err).NotTo(HaveOccurred())
		})

		By("By checking that we have a single IngressNodeFirewallNodeState object for worker-1")
		nodeStateList := &infv1alpha1.IngressNodeFirewallNodeStateList{}
		Eventually(func() bool {
			worker0Found := false
			worker1Found := false
			err := k8sClient.List(ctx, nodeStateList, []client.ListOption{}...)
			if err != nil {
				fmt.Fprintf(GinkgoWriter, "Could not list IngressNodeFirewallNodeStates during this iteration\n")
				return false
			}
			if len(nodeStateList.Items) != 1 {
				fmt.Fprintf(GinkgoWriter, "Got != 1 IngressNodeFirewallNodeStates during this interation\n")
				return false
			}
			for _, nodeState := range nodeStateList.Items {
				if nodeState.Name == "worker0" {
					worker0Found = true
				} else if nodeState.Name == "worker1" {
					worker1Found = true
				}
			}
			return worker0Found && !worker1Found
		})
	})
})
