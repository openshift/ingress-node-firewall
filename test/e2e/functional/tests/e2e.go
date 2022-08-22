package tests

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	"github.com/openshift/ingress-node-firewall/pkg/failsaferules"
	infmetrics "github.com/openshift/ingress-node-firewall/pkg/metrics"
	"github.com/openshift/ingress-node-firewall/pkg/platform"
	"github.com/openshift/ingress-node-firewall/pkg/status"
	"github.com/openshift/ingress-node-firewall/test/consts"
	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
	infwutils "github.com/openshift/ingress-node-firewall/test/e2e/ingress-node-firewall"
	"github.com/openshift/ingress-node-firewall/test/e2e/pods"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/component-base/metrics/testutil"
	ctrl "sigs.k8s.io/controller-runtime"
	goclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	OperatorNameSpace = consts.DefaultOperatorNameSpace
	TestIsOpenShift   = false
	TestInterface     = "eth0"
)

func init() {
	if len(os.Getenv("IS_OPENSHIFT")) != 0 {
		TestIsOpenShift = true
	}
	if ns := os.Getenv("OO_INSTALL_NAMESPACE"); len(ns) != 0 {
		OperatorNameSpace = ns
	}
	if intf := os.Getenv("NODE_INTERFACE"); len(intf) != 0 {
		TestInterface = intf
	}
}

var _ = Describe("Ingress Node Firewall", func() {
	Context("Platform Check", func() {
		It("should be either Kubernetes or OpenShift platform", func() {
			cfg := ctrl.GetConfigOrDie()
			platformInfo, err := platform.GetPlatformInfo(cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(platformInfo.IsOpenShift()).Should(Equal(TestIsOpenShift))
		})
	})

	Context("IngressNodeFirewall deploy", func() {
		var config *ingressnodefwv1alpha1.IngressNodeFirewallConfig
		var configCRExisted bool

		BeforeEach(func() {
			var err error
			config = &ingressnodefwv1alpha1.IngressNodeFirewallConfig{}
			err = infwutils.LoadIngressNodeFirewallConfigFromFile(config, consts.IngressNodeFirewallConfigCRFile)
			Expect(err).ToNot(HaveOccurred())
			config.SetNamespace(OperatorNameSpace)
			configCRExisted = true
			err = testclient.Client.Get(context.Background(), goclient.ObjectKey{Namespace: config.Namespace, Name: config.Name}, config)
			if errors.IsNotFound(err) {
				configCRExisted = false
				Expect(testclient.Client.Create(context.Background(), config)).Should(Succeed())
			} else {
				Expect(err).ToNot(HaveOccurred())
			}
		})

		AfterEach(func() {
			if !configCRExisted {
				daemonset, err := testclient.Client.DaemonSets(config.Namespace).Get(context.Background(), consts.IngressNodeFirewallDaemonsetName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				Expect(daemonset.OwnerReferences).ToNot(BeNil())
				Expect(daemonset.OwnerReferences[0].Kind).To(Equal("IngressNodeFirewallConfig"))

				infwutils.DeleteINFConfig(config)
			}
		})

		It("should run Ingress node firewall DaemonSet", func() {
			By("checking Ingress node firewall daemonset is in running state", func() {
				Eventually(func() bool {
					daemonset, err := testclient.Client.DaemonSets(config.Namespace).Get(context.Background(), consts.IngressNodeFirewallDaemonsetName, metav1.GetOptions{})
					if err != nil {
						return false
					}
					return daemonset.Status.DesiredNumberScheduled == daemonset.Status.NumberReady
				}, infwutils.DeployTimeout, infwutils.Interval).Should(BeTrue())

				pods, err := testclient.Client.Pods(OperatorNameSpace).List(context.Background(), metav1.ListOptions{
					LabelSelector: "component=daemon"})
				Expect(err).ToNot(HaveOccurred())

				daemonset, err := testclient.Client.DaemonSets(config.Namespace).Get(context.Background(), consts.IngressNodeFirewallDaemonsetName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				Expect(len(pods.Items)).To(Equal(int(daemonset.Status.DesiredNumberScheduled)))

				for _, pod := range pods.Items {
					Expect(pod.Status.Phase).To(Equal(corev1.PodRunning))
				}
			})
			By("checking Ingress Node Firewall Config CR status is set", func() {
				Eventually(func() bool {
					err := testclient.Client.Get(context.Background(), goclient.ObjectKey{Namespace: config.Namespace, Name: config.Name}, config)
					Expect(err).ToNot(HaveOccurred())
					if config.Status.Conditions == nil {
						return false
					}
					for _, condition := range config.Status.Conditions {
						switch condition.Type {
						case status.ConditionAvailable:
							if condition.Status == metav1.ConditionFalse {
								return false
							}
						case status.ConditionProgressing:
							if condition.Status == metav1.ConditionTrue {
								return false
							}
						case status.ConditionDegraded:
							if condition.Status == metav1.ConditionTrue {
								return false
							}
						}
					}
					return true
				}, 5*time.Minute, 5*time.Second).Should(BeTrue())
			})
		})

		It("should run Ingress node firewall apply rules and check the actions", func() {
			By("get nodes IP addresses with matching labels and ping their IPs")
			nodes, err := testclient.Client.Nodes().List(context.Background(), metav1.ListOptions{LabelSelector: consts.IngressNodeFirewallNodeLabel})
			Expect(err).ToNot(HaveOccurred())

			err, _ = infwutils.RunPingTest(nodes.Items)
			Expect(err).ToNot(HaveOccurred())

			v4CIDR, v6CIDR, err := infwutils.GetRuleCIDR(nodes.Items)
			Expect(err).ToNot(HaveOccurred())

			By("creating ingress node firewall rules")
			rules := &ingressnodefwv1alpha1.IngressNodeFirewall{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rules1",
				},
				Spec: ingressnodefwv1alpha1.IngressNodeFirewallSpec{
					NodeSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{consts.IngressNodeFirewallNodeLabel: ""},
					},
					Ingress: []ingressnodefwv1alpha1.IngressNodeFirewallRules{
						{
							SourceCIDRs: []string{v4CIDR},
							FirewallProtocolRules: []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 10,
									ProtocolConfig: ingressnodefwv1alpha1.IngressNodeProtocolConfig{
										Protocol: ingressnodefwv1alpha1.ProtocolTypeICMP,
										ICMP: &ingressnodefwv1alpha1.IngressNodeFirewallICMPRule{
											ICMPType: 8,
										},
									},
									Action: ingressnodefwv1alpha1.IngressNodeFirewallDeny,
								},
								{
									Order: 20,
									ProtocolConfig: ingressnodefwv1alpha1.IngressNodeProtocolConfig{
										Protocol: ingressnodefwv1alpha1.ProtocolTypeTCP,
										TCP: &ingressnodefwv1alpha1.IngressNodeFirewallProtoRule{
											Ports: intstr.FromString("800-900"),
										},
									},
									Action: ingressnodefwv1alpha1.IngressNodeFirewallDeny,
								},
							},
						},
						{
							SourceCIDRs: []string{v6CIDR},
							FirewallProtocolRules: []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 10,
									ProtocolConfig: ingressnodefwv1alpha1.IngressNodeProtocolConfig{
										Protocol: ingressnodefwv1alpha1.ProtocolTypeICMP6,
										ICMPv6: &ingressnodefwv1alpha1.IngressNodeFirewallICMPRule{
											ICMPType: 128,
										},
									},
									Action: ingressnodefwv1alpha1.IngressNodeFirewallDeny,
								},
							},
						},
					},
					Interfaces: []string{
						TestInterface,
					},
				},
			}
			Eventually(func() error {
				err := testclient.Client.Create(context.Background(), rules)
				return err
			}, infwutils.Timeout, infwutils.Interval).Should(Succeed())

			key := types.NamespacedName{
				Name: "rules1",
			}
			By("checking Ingress node firewall rules resource is created")
			Eventually(func() error {
				err := testclient.Client.Get(context.Background(), key, rules)
				return err
			}, infwutils.Timeout, infwutils.Interval).Should(Succeed())

			By("checking ingress node firewall nodeState resource is created")
			nodeStateList := &ingressnodefwv1alpha1.IngressNodeFirewallNodeStateList{}
			Eventually(func() bool {
				err := testclient.Client.List(context.Background(), nodeStateList)
				if err != nil {
					return false
				}
				return len(nodeStateList.Items) == len(nodes.Items)
			}, infwutils.Timeout, infwutils.Interval).Should(BeTrue())

			By("checking Ingress node firewall rules deny ping packets")
			Eventually(func() bool {
				err, cnt := infwutils.RunPingTest(nodes.Items)
				if err != nil && cnt == len(infwutils.NodesIPs(nodes.Items)) {
					return true
				}
				return false
			}, infwutils.Timeout, infwutils.Interval).Should(BeTrue())

			By("checking ingress node firewall events are generated")
			podList, err := infwutils.GetDaemonSetPods(config.Namespace)
			Expect(err).To(BeNil())
			Expect(podList).ToNot(BeNil())
			for _, pod := range podList.Items {
				out, err := pods.GetPodLogs(testclient.Client, &pod, "events")
				Expect(err).ToNot(HaveOccurred())
				Eventually(func() bool {
					ips, err := infwutils.NodeIPs(pod.Spec.NodeName)
					if err != nil {
						return false
					}
					for _, ip := range ips {
						if !strings.Contains(out, ip) {
							return false
						}
					}
					return true
				}, infwutils.Timeout, infwutils.Interval).Should(BeTrue())
			}

			By("checking Ingress node firewall rules resource is deleted")
			Eventually(func() bool {
				err := testclient.Client.Delete(context.Background(), rules)
				return errors.IsNotFound(err)
			}, infwutils.Timeout, infwutils.Interval).Should(BeTrue(), "Failed to delete IngressNodeFirewall custom resource")

			By("checking Ingress node firewall nodeState resource is deleted when firewall rules object is deleted")
			err = testclient.Client.List(context.Background(), nodeStateList)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(nodeStateList.Items)).To(BeZero())
		})
	})

	Context("Statistics", func() {
		var config *ingressnodefwv1alpha1.IngressNodeFirewallConfig
		var configCRExisted bool

		BeforeEach(func() {
			var err error
			config = &ingressnodefwv1alpha1.IngressNodeFirewallConfig{}
			err = infwutils.LoadIngressNodeFirewallConfigFromFile(config, consts.IngressNodeFirewallConfigCRFile)
			Expect(err).ToNot(HaveOccurred())
			config.SetNamespace(OperatorNameSpace)
			configCRExisted = true
			err = testclient.Client.Get(context.Background(), goclient.ObjectKey{Namespace: config.Namespace, Name: config.Name}, config)
			if errors.IsNotFound(err) {
				configCRExisted = false
				Expect(testclient.Client.Create(context.Background(), config)).Should(Succeed())
			} else {
				Expect(err).ToNot(HaveOccurred())
			}
		})

		AfterEach(func() {
			if !configCRExisted {
				daemonset, err := testclient.Client.DaemonSets(config.Namespace).Get(context.Background(), consts.IngressNodeFirewallDaemonsetName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				Expect(daemonset.OwnerReferences).ToNot(BeNil())
				Expect(daemonset.OwnerReferences[0].Kind).To(Equal("IngressNodeFirewallConfig"))

				infwutils.DeleteINFConfig(config)
			}
		})

		It("should expose at least one endpoint via a daemon metrics service", func() {
			err := wait.PollImmediate(1*time.Second, 10*time.Second, func() (done bool, err error) {
				endpointSliceList, err := testclient.Client.Endpoints(OperatorNameSpace).List(context.TODO(), metav1.ListOptions{
					LabelSelector: "app=ingress-node-firewall-daemon",
				})

				if err != nil {
					return false, err
				}

				if len(endpointSliceList.Items) == 0 {
					return false, nil
				}

				totalEndpoints := 0
				for _, slice := range endpointSliceList.Items {
					totalEndpoints += len(slice.Subsets)
				}
				if totalEndpoints > 0 {
					return true, nil
				}
				return false, nil
			})

			Expect(err).Should(BeNil())
		})

		It("should expose daemon metrics", func() {
			podList, err := infwutils.GetDaemonSetPods(config.Namespace)
			Expect(err).To(BeNil())
			Expect(podList).ToNot(BeNil())
			daemonPod := &podList.Items[0]

			nodes, err := testclient.Client.Nodes().List(context.Background(), metav1.ListOptions{LabelSelector: consts.IngressNodeFirewallNodeLabel})
			Expect(err).ToNot(HaveOccurred())

			err, _ = infwutils.RunPingTest(nodes.Items)
			Expect(err).ToNot(HaveOccurred())

			v4CIDR, _, err := infwutils.GetRuleCIDR(nodes.Items)
			Expect(err).ToNot(HaveOccurred())

			rules := &ingressnodefwv1alpha1.IngressNodeFirewall{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rules1",
				},
				Spec: ingressnodefwv1alpha1.IngressNodeFirewallSpec{
					NodeSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{consts.IngressNodeFirewallNodeLabel: ""},
					},
					Ingress: []ingressnodefwv1alpha1.IngressNodeFirewallRules{
						{
							SourceCIDRs: []string{v4CIDR},
							FirewallProtocolRules: []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 1,
									ProtocolConfig: ingressnodefwv1alpha1.IngressNodeProtocolConfig{
										Protocol: ingressnodefwv1alpha1.ProtocolTypeICMP,
										ICMP: &ingressnodefwv1alpha1.IngressNodeFirewallICMPRule{
											ICMPType: 8,
										},
									},
									Action: ingressnodefwv1alpha1.IngressNodeFirewallDeny,
								},
							},
						},
					},
					Interfaces: []string{
						TestInterface,
					},
				},
			}

			Eventually(func() error {
				err := testclient.Client.Create(context.Background(), rules)
				return err
			}, infwutils.Timeout, infwutils.Interval).Should(Succeed())

			defer Eventually(func() bool {
				err := testclient.Client.Delete(context.Background(), rules)
				return errors.IsNotFound(err)
			}, infwutils.Timeout, infwutils.Interval).Should(BeTrue(), "Failed to delete IngressNodeFirewall custom resource")

			Eventually(func() bool {
				err, cnt := infwutils.RunPingTest(nodes.Items)
				if err != nil && cnt == len(nodes.Items) {
					return true
				}
				return false
			}, infwutils.Timeout, infwutils.Interval).Should(BeTrue())

			var stdOut, stdError string
			var metrics testutil.Metrics
			err = wait.PollImmediate(1*time.Second, 60*time.Second, func() (done bool, err error) {
				stdOut, stdError, err = pods.ExecCommand(testclient.Client, daemonPod, "/usr/bin/curl", "127.0.0.1:39301/metrics")

				if err != nil {
					return false, err
				}

				if stdError != "" {
					return false, fmt.Errorf("%s", stdError)
				}

				if stdOut == "" {
					return false, nil
				}
				metrics = testutil.NewMetrics()
				if err = testutil.ParseMetrics(stdOut, &metrics); err != nil {
					return false, fmt.Errorf("failed to parse metrics: %v", err)
				}

				sample, ok := metrics[infmetrics.MetricINFNamespace+"_"+infmetrics.MetricINFSubsystemNode+"_"+"packet_deny_total"]
				if !ok {
					return false, nil
				}
				if len(sample) == 0 {
					return false, nil
				}

				if sample[0].Value == 1 {
					return true, nil
				}

				return false, nil
			})

			Expect(err).To(BeNil())
			for _, metric := range infmetrics.GetPrometheusStatisticNames() {
				sample, ok := metrics[metric]
				Expect(ok).To(BeTrue())
				Expect(sample.Len() > 0).To(BeTrue())
			}
		})
	})

	// Unit tests will be the primary location to validate the functionality of the webhook, the objective of e2e
	// tests will be to ensure basic functionality of the webhook. Any additional test cases for functionality should
	// be added to unit tests in order to aid test latency.
	Context("Webhook", func() {
		var config *ingressnodefwv1alpha1.IngressNodeFirewallConfig
		var configCRExisted bool

		BeforeEach(func() {
			var err error
			config = &ingressnodefwv1alpha1.IngressNodeFirewallConfig{}
			err = infwutils.LoadIngressNodeFirewallConfigFromFile(config, consts.IngressNodeFirewallConfigCRFile)
			Expect(err).ToNot(HaveOccurred())
			config.SetNamespace(OperatorNameSpace)
			configCRExisted = true
			err = testclient.Client.Get(context.Background(), goclient.ObjectKey{Namespace: config.Namespace, Name: config.Name}, config)
			if errors.IsNotFound(err) {
				configCRExisted = false
				Expect(testclient.Client.Create(context.Background(), config)).Should(Succeed())
			} else {
				Expect(err).ToNot(HaveOccurred())
			}
		})

		AfterEach(func() {
			if !configCRExisted {
				daemonset, err := testclient.Client.DaemonSets(config.Namespace).Get(context.Background(), consts.IngressNodeFirewallDaemonsetName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				Expect(daemonset.OwnerReferences).ToNot(BeNil())
				Expect(daemonset.OwnerReferences[0].Kind).To(Equal("IngressNodeFirewallConfig"))
				infwutils.DeleteINFConfig(config)
			}
		})

		It("should allow valid ingressnodefirewall TCP rule", func() {
			inf := infwutils.GetINF(OperatorNameSpace, "e2e-webhook-valid-tcp")
			infwutils.DefineWithWorkerNodeSelector(inf)
			infwutils.DefineWithInterface(inf, TestInterface)
			infwutils.DefineDenyTCPRule(inf, "1.1.1.1/32", 40000)
			Expect(testclient.Client.Create(context.Background(), inf)).To(Succeed())
			cleanNodeFirewallRule(inf)
		})

		It("should allow valid ingressnodefirewall UDP rule", func() {
			inf := infwutils.GetINF(OperatorNameSpace, "e2e-webhook-valid-udp")
			infwutils.DefineWithWorkerNodeSelector(inf)
			infwutils.DefineWithInterface(inf, TestInterface)
			infwutils.DefineDenyUDPRule(inf, "1.1.1.1/32", 40000)
			Expect(testclient.Client.Create(context.Background(), inf)).To(Succeed())
			cleanNodeFirewallRule(inf)
		})

		It("should allow valid ingressnodefirewall ICMPV4 rule", func() {
			inf := infwutils.GetINF(OperatorNameSpace, "e2e-webhook-valid-icmpv4")
			infwutils.DefineWithWorkerNodeSelector(inf)
			infwutils.DefineWithInterface(inf, TestInterface)
			infwutils.DefineDenyICMPV4Rule(inf, "1.1.1.1/32")
			Expect(testclient.Client.Create(context.Background(), inf)).To(Succeed())
			cleanNodeFirewallRule(inf)
		})

		It("should allow valid ingressnodefirewall ICMPV6 rule", func() {
			inf := infwutils.GetINF(OperatorNameSpace, "e2e-webhook-valid-icmpv6")
			infwutils.DefineWithWorkerNodeSelector(inf)
			infwutils.DefineWithInterface(inf, TestInterface)
			infwutils.DefineDenyICMPV6Rule(inf, "1:1:1::1/64")
			Expect(testclient.Client.Create(context.Background(), inf)).To(Succeed())
			cleanNodeFirewallRule(inf)
		})

		It("should allow valid ingressnodefirewall SCTP rule", func() {
			inf := infwutils.GetINF(OperatorNameSpace, "e2e-webhook-valid-sctp")
			infwutils.DefineWithWorkerNodeSelector(inf)
			infwutils.DefineWithInterface(inf, TestInterface)
			infwutils.DefineDenySCTPRule(inf, "1.1.1.1/32", 40000)
			Expect(testclient.Client.Create(context.Background(), inf)).To(Succeed())
			cleanNodeFirewallRule(inf)
		})

		It("should block any rules which conflict with failsafe rules", func() {
			for _, tcpFailSafeRule := range failsaferules.GetTCP() {
				inf := infwutils.GetINF(OperatorNameSpace, fmt.Sprintf("e2e-webhook-block-conflict-%s-tcp", tcpFailSafeRule.GetServiceName()))
				infwutils.DefineWithWorkerNodeSelector(inf)
				infwutils.DefineWithInterface(inf, TestInterface)
				infwutils.DefineDenyTCPRule(inf, "1.1.1.1/32", tcpFailSafeRule.GetPort())
				Expect(testclient.Client.Create(context.Background(), inf)).ToNot(Succeed())
				cleanNodeFirewallRule(inf)
			}
			for _, udpFailSafeRule := range failsaferules.GetUDP() {
				inf := infwutils.GetINF(OperatorNameSpace, fmt.Sprintf("e2e-webhook-block-conflict-%s-udp", udpFailSafeRule.GetServiceName()))
				infwutils.DefineWithWorkerNodeSelector(inf)
				infwutils.DefineWithInterface(inf, TestInterface)
				infwutils.DefineDenyUDPRule(inf, "1.1.1.1/32", udpFailSafeRule.GetPort())
				Expect(testclient.Client.Create(context.Background(), inf)).ToNot(Succeed())
				cleanNodeFirewallRule(inf)
			}
		})
	})
})

func cleanNodeFirewallRule(inf *ingressnodefwv1alpha1.IngressNodeFirewall) {
	nodeStateList := &ingressnodefwv1alpha1.IngressNodeFirewallNodeStateList{}

	Eventually(func() bool {
		err := testclient.Client.Delete(context.Background(), inf)
		return errors.IsNotFound(err)
	}, infwutils.Timeout, infwutils.Interval).Should(BeTrue())
	err := testclient.Client.List(context.Background(), nodeStateList)
	Expect(err).ToNot(HaveOccurred())
	Expect(len(nodeStateList.Items)).To(BeZero())
}
