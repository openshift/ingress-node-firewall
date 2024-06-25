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

const (
	timeout  = time.Second * 10
	interval = time.Millisecond * 250
)

var _ = Describe("IngressNodeFirewall controller", func() {
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
			By(fmt.Sprintf("Creating node %s", node.Name))
			Expect(k8sClient.Create(ctx, &node)).Should(Succeed())
		}

		By("Creating a new IngressNodeFirewall object that matches the worker label")
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
			Status: infv1alpha1.IngressNodeFirewallStatus{
				SyncStatus: infv1alpha1.FirewallRulesSyncOK,
			},
		}

		Expect(k8sClient.Create(ctx, &ingressNodeFirewall)).Should(Succeed())
	})

	AfterEach(func() {
		Expect(k8sClient.DeleteAllOf(context.Background(), &infv1alpha1.IngressNodeFirewall{})).Should(Succeed())
		Expect(k8sClient.DeleteAllOf(context.Background(), &v1.Node{})).Should(Succeed())
		Eventually(func() bool {
			nodeStateList := &infv1alpha1.IngressNodeFirewallNodeStateList{}
			err := k8sClient.List(ctx, nodeStateList)
			if err != nil {
				fmt.Fprintf(GinkgoWriter, "Could not list IngressNodeFirewallNodeStates on cleanup, err: %q", err)
				return false
			}
			return len(nodeStateList.Items) == 0
		}).Should(BeTrue())
	})

	// I) Baseline test.
	When("an IngressNodeFirewall object is created that matches all worker nodes", func() {
		It("All worker nodes should have a valid IngressNodeFirewallNodeState", func() {
			By("Checking that we have an IngressNodeFirewallNodeState object on every worker node")
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
					if _, ok := nodeState.Spec.InterfaceIngressRules["eth0"]; !ok {
						fmt.Fprintf(GinkgoWriter,
							"IngressNodeFirewallNodeState.Spec.InterfaceIngressRules[%s] does not exist "+
								"for object with name %s\n", "eth0", nodeState.Name)
						return false
					}
					if !equality.Semantic.DeepEqual(nodeState.Spec.InterfaceIngressRules["eth0"], rules) {
						fmt.Fprintf(GinkgoWriter,
							"IngressNodeFirewallNodeState.Spec.Ingress does not match IngressNodeFirewall.Spec.Ingress "+
								"for object with name %s\n", nodeState.Name)
						return false
					}
				}

				return true
			}, timeout, interval).Should(BeTrue())
		})
	})

	// II) Test updates to IngressNodeFirewallNodeState node selectors.
	When("the IngressNodeFirewallNodeState nodeSelector is updated", func() {
		// Test updates to IngressNodeFirewalls - empty node selector.
		When("the nodeSelector is updated to an empty node selector", func() {
			It("The IngressNodeFirewallNodeState objects should match all nodes", func() {
				By("Waiting for the expected list of IngressNodeFirewallNodeStates")
				hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{"worker-0", "worker-1"})

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

				By("Checking that we have all IngressNodeFirewallNodeState objects")
				hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{"worker-0", "worker-1", "control-plane-0"})
			})
		})

		// Test updates to IngressNodeFirewalls - match another label.
		When("the nodeSelector is updated to match label \"ingress-node-firewall\"=\"enabled\",", func() {
			It("The IngressNodeFirewallNodeState object for worker-1 should be deleted", func() {
				By("Waiting for the expected list of IngressNodeFirewallNodeStates")
				hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{"worker-0", "worker-1"})

				By(fmt.Sprintf("Updating the nodeSelector on IngressNodeFirewall %s", ingressNodeFirewallName))
				err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
					inf := &infv1alpha1.IngressNodeFirewall{}
					key := types.NamespacedName{Name: ingressNodeFirewallName}
					Expect(k8sClient.Get(ctx, key, inf)).Should(Succeed())
					inf.Spec.NodeSelector = metav1.LabelSelector{
						MatchLabels: map[string]string{
							"ingress-node-firewall": "enabled",
						},
					}
					return k8sClient.Update(ctx, inf)
				})
				Expect(err).NotTo(HaveOccurred())

				By("Checking that we have only an IngressNodeFirewallNodeState for worker-0")
				hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{"worker-0"})
			})
		})

		// Test updates to IngressNodeFirewalls - match a non-existing label.
		When("the nodeSelector is updated to match label \"label\"=\"does-not-exist\",", func() {
			It("The IngressNodeFirewallNodeState object for both workers should be deleted", func() {
				By("Waiting for the expected list of IngressNodeFirewallNodeStates")
				hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{})

				By(fmt.Sprintf("Updating the nodeSelector on IngressNodeFirewall %s", ingressNodeFirewallName))
				err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
					inf := &infv1alpha1.IngressNodeFirewall{}
					key := types.NamespacedName{Name: ingressNodeFirewallName}
					Expect(k8sClient.Get(ctx, key, inf)).Should(Succeed())
					inf.Spec.NodeSelector = metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label": "does-not-exist",
						},
					}
					return k8sClient.Update(ctx, inf)
				})
				Expect(err).NotTo(HaveOccurred())

				By("Checking that we have no IngressNodeFirewallNodeState object")
				hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{})
			})
		})
	})

	// III) Test updates to node labels.
	When("a node's label is updated", func() {
		When("the label on worker-1 is removed", func() {
			It("The IngressNodeFirewallNodeState object for worker-1 should be deleted", func() {
				By("Waiting for the expected list of IngressNodeFirewallNodeStates")
				hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{"worker-0", "worker-1"})

				By("Updating the label on node worker-1")
				err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
					node := &v1.Node{}
					key := types.NamespacedName{Name: "worker-1"}
					Expect(k8sClient.Get(ctx, key, node)).Should(Succeed())
					node.Labels = map[string]string{}
					return k8sClient.Update(ctx, node)
				})
				Expect(err).NotTo(HaveOccurred())

				By("Checking that we have a single IngressNodeFirewallNodeState object for worker-0")
				hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{"worker-0"})
			})
		})

		When("label \"node-role.kubernetes.io/worker\"=\"\" is added to control-plane-0", func() {
			It("The IngressNodeFirewallNodeState object for control-plane-0 should be created", func() {
				By("Waiting for the expected list of IngressNodeFirewallNodeStates")
				hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{"worker-0", "worker-1"})

				By("Updating the label on node worker-1")
				err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
					node := &v1.Node{}
					key := types.NamespacedName{Name: "control-plane-0"}
					Expect(k8sClient.Get(ctx, key, node)).Should(Succeed())
					node.Labels = map[string]string{
						"node-role.kubernetes.io/worker": "",
					}
					return k8sClient.Update(ctx, node)
				})
				Expect(err).NotTo(HaveOccurred())

				By("Checking that we have IngressNodeFirewallNodeState objects for all nodes")
				hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{"worker-0", "worker-1", "control-plane-0"})
			})
		})
	})

	// IV) Test deletion of IngressNodeFirewall objects.
	When("the IngressNodeFirewallNodeState object if deleted", func() {
		It("The IngressNodeFirewallNodeState objects should be deleted as well", func() {
			By("Waiting for the expected list of IngressNodeFirewallNodeStates")
			hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{"worker-0", "worker-1"})

			By(fmt.Sprintf("Deleting the IngressNodeFirewall %s", ingressNodeFirewallName))
			err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				inf := &infv1alpha1.IngressNodeFirewall{}
				key := types.NamespacedName{Name: ingressNodeFirewallName}
				Expect(k8sClient.Get(ctx, key, inf)).Should(Succeed())
				return k8sClient.Delete(ctx, inf)
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking that we have no IngressNodeFirewallNodeState objects")
			hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{})
		})
	})
})

var _ = Describe("IngressNodeFirewall controller with multiple objects", func() {
	ctx := context.Background()

	ingressNodeFirewallName1 := "firewall1"
	rules1 := []infv1alpha1.IngressNodeFirewallRules{
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
	ingressNodeFirewallName2 := "firewall2"
	rules2 := []infv1alpha1.IngressNodeFirewallRules{
		{
			SourceCIDRs: []string{"20.0.0.0"},
			FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
				{
					Order: 10,
					ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
						Protocol: infv1alpha1.ProtocolTypeTCP,
						TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
							Ports: intstr.FromInt(8080),
						},
					},
					Action: infv1alpha1.IngressNodeFirewallAllow,
				},
			},
		},
	}
	rules := append(rules1, rules2...)
	interfaces := []string{"eth0"}

	BeforeEach(func() {
		node := v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "worker-0",
				Labels: map[string]string{
					"test.ingress.node.firewall/base":    "",
					"test.ingress.node.firewall/overlay": "",
				},
			},
		}
		By(fmt.Sprintf("Creating node %s", node.Name))
		Expect(k8sClient.Create(ctx, &node)).Should(Succeed())

		By("Creating a new IngressNodeFirewall objects that matches the base label")
		ingressNodeFirewall1 := infv1alpha1.IngressNodeFirewall{
			TypeMeta:   metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{Name: ingressNodeFirewallName1},
			Spec: infv1alpha1.IngressNodeFirewallSpec{
				NodeSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"test.ingress.node.firewall/base": ""},
				},
				Ingress:    rules1,
				Interfaces: interfaces,
			},
			Status: infv1alpha1.IngressNodeFirewallStatus{
				SyncStatus: infv1alpha1.FirewallRulesSyncOK,
			},
		}

		Expect(k8sClient.Create(ctx, &ingressNodeFirewall1)).Should(Succeed())
		By("Creating a new IngressNodeFirewall objects that matches the overlay label")
		ingressNodeFirewall2 := infv1alpha1.IngressNodeFirewall{
			TypeMeta:   metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{Name: ingressNodeFirewallName2},
			Spec: infv1alpha1.IngressNodeFirewallSpec{
				NodeSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"test.ingress.node.firewall/overlay": ""},
				},
				Ingress:    rules2,
				Interfaces: interfaces,
			},
			Status: infv1alpha1.IngressNodeFirewallStatus{
				SyncStatus: infv1alpha1.FirewallRulesSyncOK,
			},
		}

		Expect(k8sClient.Create(ctx, &ingressNodeFirewall2)).Should(Succeed())
	})

	AfterEach(func() {
		Expect(k8sClient.DeleteAllOf(context.Background(), &infv1alpha1.IngressNodeFirewall{})).Should(Succeed())
		Expect(k8sClient.DeleteAllOf(context.Background(), &v1.Node{})).Should(Succeed())
		Eventually(func() bool {
			nodeStateList := &infv1alpha1.IngressNodeFirewallNodeStateList{}
			err := k8sClient.List(ctx, nodeStateList)
			if err != nil {
				fmt.Fprintf(GinkgoWriter, "Could not list IngressNodeFirewallNodeStates on cleanup, err: %q", err)
				return false
			}
			return len(nodeStateList.Items) == 0
		}).Should(BeTrue())
	})

	// I) Baseline test.
	When("an IngressNodeFirewall object is created that matches all worker nodes", func() {
		It("All worker nodes should have a valid IngressNodeFirewallNodeState", func() {
			By("Checking that we have an IngressNodeFirewallNodeState object on every worker node")
			nodeStateList := &infv1alpha1.IngressNodeFirewallNodeStateList{}
			expectedNodeNames := []string{"worker-0"}
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
					if _, ok := nodeState.Spec.InterfaceIngressRules["eth0"]; !ok {
						fmt.Fprintf(GinkgoWriter,
							"IngressNodeFirewallNodeState.Spec.InterfaceIngressRules[%s] does not exist "+
								"for object with name %s\n", "eth0", nodeState.Name)
						return false
					}
					if !equality.Semantic.DeepEqual(nodeState.Spec.InterfaceIngressRules["eth0"], rules) {
						fmt.Fprintf(GinkgoWriter,
							"IngressNodeFirewallNodeState.Spec.Ingress does not match IngressNodeFirewall.Spec.Ingress "+
								"for object with name %s\n", nodeState.Name)
						return false
					}
				}

				return true
			}, timeout, interval).Should(BeTrue())
		})
	})
	// II) node labels updated.
	When("a node's label is updated", func() {
		When("the label base on worker-0 is removed", func() {
			It("The IngressNodeFirewallNodeState object for worker-0 with overlay label only", func() {
				By("Waiting for the expected list of IngressNodeFirewallNodeStates")
				hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{"worker-0"})

				By("Removing the label base from node worker-0")
				err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
					node := &v1.Node{}
					key := types.NamespacedName{Name: "worker-0"}
					Expect(k8sClient.Get(ctx, key, node)).Should(Succeed())
					node.Labels = map[string]string{
						"test.ingress.node.firewall/overlay": "",
					}
					return k8sClient.Update(ctx, node)
				})
				Expect(err).NotTo(HaveOccurred())

				By("Checking that we have IngressNodeFirewallNodeState object for rules2 only for worker-0")
				hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{"worker-0"})
				nodeStateList := &infv1alpha1.IngressNodeFirewallNodeStateList{}
				Eventually(func() bool {
					err := k8sClient.List(ctx, nodeStateList, []client.ListOption{}...)
					if err != nil {
						fmt.Fprintf(GinkgoWriter, "Could not list IngressNodeFirewallNodeStates during this iteration\n")
						return false
					}
					// Check item content.
					for _, nodeState := range nodeStateList.Items {
						if _, ok := nodeState.Spec.InterfaceIngressRules["eth0"]; !ok {
							fmt.Fprintf(GinkgoWriter,
								"IngressNodeFirewallNodeState.Spec.InterfaceIngressRules[%s] does not exist "+
									"for object with name %s\n", "eth0", nodeState.Name)
							return false
						}
						if !equality.Semantic.DeepEqual(nodeState.Spec.InterfaceIngressRules["eth0"], rules2) {
							fmt.Fprintf(GinkgoWriter,
								"IngressNodeFirewallNodeState.Spec.Ingress does not match IngressNodeFirewall.Spec.Ingress "+
									"for object with name %s %v\n", nodeState.Name, nodeState.Spec.InterfaceIngressRules["eth0"])
							return false
						}
					}

					return true
				}, timeout, interval).Should(BeTrue())
			})

			It("The IngressNodeFirewallNodeState object for worker-0 with base label only", func() {
				By("Waiting for the expected list of IngressNodeFirewallNodeStates")
				hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{"worker-0"})

				By("Removing the label overlay from node worker-0")
				err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
					node := &v1.Node{}
					key := types.NamespacedName{Name: "worker-0"}
					Expect(k8sClient.Get(ctx, key, node)).Should(Succeed())
					node.Labels = map[string]string{
						"test.ingress.node.firewall/base": "",
					}
					return k8sClient.Update(ctx, node)
				})
				Expect(err).NotTo(HaveOccurred())

				By("Checking that we have IngressNodeFirewallNodeState object for rules1 only for worker-0")
				hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{"worker-0"})
				nodeStateList := &infv1alpha1.IngressNodeFirewallNodeStateList{}
				Eventually(func() bool {
					err := k8sClient.List(ctx, nodeStateList, []client.ListOption{}...)
					if err != nil {
						fmt.Fprintf(GinkgoWriter, "Could not list IngressNodeFirewallNodeStates during this iteration\n")
						return false
					}
					// Check item content.
					for _, nodeState := range nodeStateList.Items {
						if _, ok := nodeState.Spec.InterfaceIngressRules["eth0"]; !ok {
							fmt.Fprintf(GinkgoWriter,
								"IngressNodeFirewallNodeState.Spec.InterfaceIngressRules[%s] does not exist "+
									"for object with name %s\n", "eth0", nodeState.Name)
							return false
						}
						if !equality.Semantic.DeepEqual(nodeState.Spec.InterfaceIngressRules["eth0"], rules1) {
							fmt.Fprintf(GinkgoWriter,
								"IngressNodeFirewallNodeState.Spec.Ingress does not match IngressNodeFirewall.Spec.Ingress "+
									"for object with name %s %v\n", nodeState.Name, nodeState.Spec.InterfaceIngressRules["eth0"])
							return false
						}
					}

					return true
				}, timeout, interval).Should(BeTrue())
			})
		})
	})
})

// hasIngressNodeFirewallNodeStates is a helper function to reduce code duplication.
// This function will list all IngressNodeFirewallNodeStates, and it will make sure that eventually an object
// with each of the expected names exists.
func hasIngressNodeFirewallNodeStates(ctx context.Context, k8sClient client.Client, expectedObjectNames []string) {
	nodeStateList := &infv1alpha1.IngressNodeFirewallNodeStateList{}
	Eventually(func() bool {
		// List all IngressNodeFirewallNodeStates.
		err := k8sClient.List(ctx, nodeStateList, []client.ListOption{}...)
		if err != nil {
			fmt.Fprintf(GinkgoWriter, "Could not list IngressNodeFirewallNodeStates during this iteration\n")
			return false
		}
		// Check number of items.
		if len(nodeStateList.Items) != len(expectedObjectNames) {
			fmt.Fprintf(GinkgoWriter, "Could not find the desired number of IngressNodeFirewallNodeStates. "+
				"Found %d objects but expected to find %d objects. Object list: %+v\n",
				len(nodeStateList.Items), len(expectedObjectNames), nodeStateList.Items)
			return false
		}
		// Check object names.
		for _, expectedName := range expectedObjectNames {
			match := false
			for _, nodeState := range nodeStateList.Items {
				if expectedName == nodeState.Name {
					match = true
					break
				}
			}
			if !match {
				fmt.Fprintf(GinkgoWriter, "Could not find expected IngressNodeFirewallNodeState %s.  Object list: %v\n",
					expectedName, nodeStateList.Items)
				return false
			}
		}
		// If we get here, return true.
		return true
	}).Should(BeTrue())
}
