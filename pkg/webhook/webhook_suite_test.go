/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	"github.com/openshift/ingress-node-firewall/pkg/failsaferules"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	//+kubebuilder:scaffold:imports
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment
var ctx context.Context
var cancel context.CancelFunc

const (
	ipv4CIDR          = "192.168.1.0/24"
	badIPV4CIDR       = "192.168.a.0/24"
	ipv6CIDR          = "2002::1234:abcd:ffff:c0a8:101/64"
	badIPV6CIDR       = "2002::1234:abcd:ffff:c0a8:101/a"
	icmpTypeEchoReply = 0
	validOrder        = 1
	validPort         = "80"
	validPortRange    = "80-90"
	invalidPortRangeA = "90-80"
	invalidPortRangeB = "90-90"
	invalidPortRangeC = "-90"
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Webhook Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: false,
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			Paths: []string{filepath.Join("..", "..", "config", "webhook")},
		},
	}

	var err error
	// cfg is defined in this file globally.
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())
	scheme := runtime.NewScheme()
	err = ingressnodefwv1alpha1.AddToScheme(scheme)
	Expect(err).NotTo(HaveOccurred())

	err = admissionv1beta1.AddToScheme(scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	// start webhook server using Manager
	webhookInstallOptions := &testEnv.WebhookInstallOptions
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:             scheme,
		Host:               webhookInstallOptions.LocalServingHost,
		Port:               webhookInstallOptions.LocalServingPort,
		CertDir:            webhookInstallOptions.LocalServingCertDir,
		LeaderElection:     false,
		MetricsBindAddress: "0",
	})

	Expect(err).NotTo(HaveOccurred())

	err = (&IngressNodeFirewallWebhook{}).SetupWebhookWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:webhook

	go func() {
		defer GinkgoRecover()
		err = mgr.Start(ctx)
		Expect(err).NotTo(HaveOccurred())
	}()

	// wait for the webhook server to get ready
	dialer := &net.Dialer{Timeout: time.Second}
	addrPort := fmt.Sprintf("%s:%d", webhookInstallOptions.LocalServingHost, webhookInstallOptions.LocalServingPort)
	Eventually(func() error {
		conn, err := tls.DialWithDialer(dialer, "tcp", addrPort, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}).Should(Succeed())

}, 60)

var _ = Describe("Rules", func() {
	Context("protocol is ICMPv4", func() {
		var inf *ingressnodefwv1alpha1.IngressNodeFirewall

		BeforeEach(func() {
			inf = getIngressNodeFirewall("rulesicmpv4")
			initCIDRICMPRule(inf, ipv4CIDR, validOrder, false, icmpTypeEchoReply, icmpTypeEchoReply, ingressnodefwv1alpha1.IngressNodeFirewallAllow)
		})

		It("allows valid rule", func() {
			Expect(createIngressNodeFirewall(inf)).To(Succeed())
			Expect(deleteIngressNodeFirewall(inf)).To(Succeed())
		})

		It("rejects rule with no ICMP details defined", func() {
			inf.Spec.Ingress[0].FirewallProtocolRules[0].ICMPRule = nil
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rejects rule with port defined", func() {
			portRule := &ingressnodefwv1alpha1.IngressNodeFirewallProtoRule{Ports: validPort}
			inf.Spec.Ingress[0].FirewallProtocolRules[0].ProtocolRule = portRule
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})
	})

	Context("protocol is ICMPv6", func() {
		var inf *ingressnodefwv1alpha1.IngressNodeFirewall

		BeforeEach(func() {
			inf = getIngressNodeFirewall("rulesicmpv6")
			initCIDRICMPRule(inf, ipv6CIDR, validOrder, false, icmpTypeEchoReply, icmpTypeEchoReply, ingressnodefwv1alpha1.IngressNodeFirewallAllow)
		})

		It("allows valid rule", func() {
			Expect(createIngressNodeFirewall(inf)).To(Succeed())
			Expect(deleteIngressNodeFirewall(inf)).To(Succeed())
		})

		It("rejects rule with no ICMP details defined", func() {
			inf.Spec.Ingress[0].FirewallProtocolRules[0].ICMPRule = nil
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rejects rule with port defined", func() {
			portRule := &ingressnodefwv1alpha1.IngressNodeFirewallProtoRule{Ports: validPort}
			inf.Spec.Ingress[0].FirewallProtocolRules[0].ProtocolRule = portRule
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rejects rule with port defined", func() {
			portRule := &ingressnodefwv1alpha1.IngressNodeFirewallProtoRule{Ports: validPort}
			inf.Spec.Ingress[0].FirewallProtocolRules[0].ProtocolRule = portRule
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})
	})

	Context("protocol is TCP", func() {
		var inf *ingressnodefwv1alpha1.IngressNodeFirewall
		BeforeEach(func() {
			inf = getIngressNodeFirewall("rulestcp")
		})

		It("accepts rule with port range defined", func() {
			initCIDRTransportRule(inf, ipv4CIDR, validOrder, ingressnodefwv1alpha1.ProtocolTypeTCP, validPortRange, ingressnodefwv1alpha1.IngressNodeFirewallAllow)
			Expect(createIngressNodeFirewall(inf)).To(Succeed())
			Expect(deleteIngressNodeFirewall(inf))
		})

		It("rejects rule with port range defined where start is greater than end", func() {
			initCIDRTransportRule(inf, ipv4CIDR, validOrder, ingressnodefwv1alpha1.ProtocolTypeTCP, invalidPortRangeA, ingressnodefwv1alpha1.IngressNodeFirewallAllow)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rejects rule with port range defined where start and end range are equal", func() {
			initCIDRTransportRule(inf, ipv4CIDR, validOrder, ingressnodefwv1alpha1.ProtocolTypeTCP, invalidPortRangeB, ingressnodefwv1alpha1.IngressNodeFirewallAllow)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rejects rule with port range defined where only end is defined", func() {
			initCIDRTransportRule(inf, ipv4CIDR, validOrder, ingressnodefwv1alpha1.ProtocolTypeTCP, invalidPortRangeC, ingressnodefwv1alpha1.IngressNodeFirewallAllow)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rejects rule with no port defined", func() {
			initCIDRTransportRule(inf, ipv4CIDR, validOrder, ingressnodefwv1alpha1.ProtocolTypeTCP, validPort, ingressnodefwv1alpha1.IngressNodeFirewallAllow)
			inf.Spec.Ingress[0].FirewallProtocolRules[0].ProtocolRule = nil
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rejects rule with port as 0", func() {
			initCIDRTransportRule(inf, ipv4CIDR, validOrder, ingressnodefwv1alpha1.ProtocolTypeTCP, "0", ingressnodefwv1alpha1.IngressNodeFirewallAllow)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rejects rule with port greater than 65535", func() {
			initCIDRTransportRule(inf, ipv4CIDR, validOrder, ingressnodefwv1alpha1.ProtocolTypeTCP, "65536", ingressnodefwv1alpha1.IngressNodeFirewallAllow)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})
	})

	Context("Meta", func() {
		var inf *ingressnodefwv1alpha1.IngressNodeFirewall

		BeforeEach(func() {
			inf = getIngressNodeFirewall("meta")
			initCIDRTransportRule(inf, ipv4CIDR, validOrder, ingressnodefwv1alpha1.ProtocolTypeTCP, validPort, ingressnodefwv1alpha1.IngressNodeFirewallAllow)
		})

		It("restricts rule count", func() {
			firstRule := inf.Spec.Ingress[0].FirewallProtocolRules
			var i uint32
			for ; i < uint32(failsaferules.MAX_INGRESS_RULES+1); i++ {
				firstRule = append(firstRule, getTCPUDPRule(i, ingressnodefwv1alpha1.ProtocolTypeTCP, validPort, ingressnodefwv1alpha1.IngressNodeFirewallAllow))
			}
			inf.Spec.Ingress[0].FirewallProtocolRules = firstRule
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("only unique order is allowed", func() {
			// adding another rule with the same order integer
			inf.Spec.Ingress[0].FirewallProtocolRules = append(inf.Spec.Ingress[0].FirewallProtocolRules,
				getTCPUDPRule(validOrder, ingressnodefwv1alpha1.ProtocolTypeTCP, validPort, ingressnodefwv1alpha1.IngressNodeFirewallAllow))
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})
	})
})

var _ = Describe("sourceCIDRs", func() {
	var inf *ingressnodefwv1alpha1.IngressNodeFirewall

	BeforeEach(func() {
		inf = getIngressNodeFirewall("sourcecidrs")
	})

	Context("and its IPV4", func() {
		It("allows valid CIDR", func() {
			initCIDRTransportRule(inf, ipv4CIDR, validOrder, ingressnodefwv1alpha1.ProtocolTypeTCP, validPort, ingressnodefwv1alpha1.IngressNodeFirewallAllow)
			Expect(createIngressNodeFirewall(inf)).To(Succeed())
			Expect(deleteIngressNodeFirewall(inf)).To(Succeed())
		})

		It("rejects invalid CIDR", func() {
			initCIDRTransportRule(inf, badIPV4CIDR, validOrder, ingressnodefwv1alpha1.ProtocolTypeTCP, validPort, ingressnodefwv1alpha1.IngressNodeFirewallAllow)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})
	})

	Context("and its IPV6", func() {
		It("allows valid CIDR", func() {
			initCIDRTransportRule(inf, ipv6CIDR, validOrder, ingressnodefwv1alpha1.ProtocolTypeTCP, validPort, ingressnodefwv1alpha1.IngressNodeFirewallAllow)
			Expect(createIngressNodeFirewall(inf)).To(Succeed())
			Expect(deleteIngressNodeFirewall(inf)).To(Succeed())
		})

		It("rejects invalid CIDR", func() {
			initCIDRTransportRule(inf, badIPV6CIDR, validOrder, ingressnodefwv1alpha1.ProtocolTypeTCP, validPort, ingressnodefwv1alpha1.IngressNodeFirewallAllow)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})
	})
})

var _ = Describe("Pin holes", func() {
	var inf *ingressnodefwv1alpha1.IngressNodeFirewall

	BeforeEach(func() {
		inf = getIngressNodeFirewall("pinholes")
	})

	Context("will block", func() {
		It("rules which conflict with API server access", func() {
			initCIDRTransportRule(inf, ipv4CIDR, 1, ingressnodefwv1alpha1.ProtocolTypeTCP, "6443", ingressnodefwv1alpha1.IngressNodeFirewallDeny)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rules which contain a port range which conflicts with API server access", func() {
			initCIDRTransportRule(inf, ipv4CIDR, 1, ingressnodefwv1alpha1.ProtocolTypeTCP, "6440-6444", ingressnodefwv1alpha1.IngressNodeFirewallDeny)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rule which conflict with DHCP", func() {
			initCIDRTransportRule(inf, ipv4CIDR, 1, ingressnodefwv1alpha1.ProtocolTypeUDP, "68", ingressnodefwv1alpha1.IngressNodeFirewallDeny)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rule which contain a port range which conflicts with DHCP", func() {
			initCIDRTransportRule(inf, ipv4CIDR, 1, ingressnodefwv1alpha1.ProtocolTypeUDP, "60-68", ingressnodefwv1alpha1.IngressNodeFirewallDeny)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rule which conflict with ETCD 2380", func() {
			initCIDRTransportRule(inf, ipv4CIDR, 1, ingressnodefwv1alpha1.ProtocolTypeTCP, "2380", ingressnodefwv1alpha1.IngressNodeFirewallDeny)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rule which contain a port range which conflicts with ETCD 2380", func() {
			initCIDRTransportRule(inf, ipv4CIDR, 1, ingressnodefwv1alpha1.ProtocolTypeTCP, "2380-2381", ingressnodefwv1alpha1.IngressNodeFirewallDeny)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rule which conflict with ETCD 2379", func() {
			initCIDRTransportRule(inf, ipv4CIDR, 1, ingressnodefwv1alpha1.ProtocolTypeTCP, "2379", ingressnodefwv1alpha1.IngressNodeFirewallDeny)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rule which contain a port range which conflicts with ETCD 2379", func() {
			initCIDRTransportRule(inf, ipv4CIDR, 1, ingressnodefwv1alpha1.ProtocolTypeTCP, "1-59999", ingressnodefwv1alpha1.IngressNodeFirewallDeny)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})

		It("rule which conflict with SSH", func() {
			initCIDRTransportRule(inf, ipv4CIDR, 1, ingressnodefwv1alpha1.ProtocolTypeTCP, "22", ingressnodefwv1alpha1.IngressNodeFirewallDeny)
			Expect(createIngressNodeFirewall(inf)).ToNot(Succeed())
		})
	})

	Context("will allow", func() {
		It("rules which are close API server address", func() {
			initCIDRTransportRule(inf, ipv4CIDR, 1, ingressnodefwv1alpha1.ProtocolTypeTCP, "6441-6442", ingressnodefwv1alpha1.IngressNodeFirewallDeny)
			Expect(createIngressNodeFirewall(inf)).To(Succeed())
			Expect(deleteIngressNodeFirewall(inf)).To(Succeed())
		})

	})
})

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

func createIngressNodeFirewall(inf *ingressnodefwv1alpha1.IngressNodeFirewall) error {
	return k8sClient.Create(ctx, inf)
}

func deleteIngressNodeFirewall(inf *ingressnodefwv1alpha1.IngressNodeFirewall) error {
	return k8sClient.Delete(ctx, inf)
}

func getIngressNodeFirewall(name string) *ingressnodefwv1alpha1.IngressNodeFirewall {
	return &ingressnodefwv1alpha1.IngressNodeFirewall{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: ingressnodefwv1alpha1.IngressNodeFirewallSpec{},
	}
}

func initCIDRTransportRule(inf *ingressnodefwv1alpha1.IngressNodeFirewall, cidr string, order uint32, protocol ingressnodefwv1alpha1.IngressNodeFirewallRuleProtocolType,
	ports string, action ingressnodefwv1alpha1.IngressNodeFirewallActionType) {

	rule := ingressnodefwv1alpha1.IngressNodeFirewallRules{
		SourceCIDRs: []string{cidr},
		FirewallProtocolRules: []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
			getTCPUDPRule(order, protocol, ports, action),
		},
	}
	if inf.Spec.Ingress == nil {
		inf.Spec.Ingress = make([]ingressnodefwv1alpha1.IngressNodeFirewallRules, 0)
	}
	inf.Spec.Ingress = append(inf.Spec.Ingress, rule)
}

func initCIDRICMPRule(inf *ingressnodefwv1alpha1.IngressNodeFirewall, cidr string, order uint32, isICMPV6 bool, icmpType, icmpCode uint8,
	action ingressnodefwv1alpha1.IngressNodeFirewallActionType) {

	icmpVer := ingressnodefwv1alpha1.ProtocolTypeICMP
	if isICMPV6 {
		icmpVer = ingressnodefwv1alpha1.ProtocolTypeICMP6
	}

	rule := ingressnodefwv1alpha1.IngressNodeFirewallRules{
		SourceCIDRs: []string{cidr},
		FirewallProtocolRules: []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
			getICMPRule(order, icmpVer, icmpType, icmpCode, action),
		},
	}
	if inf.Spec.Ingress == nil {
		inf.Spec.Ingress = make([]ingressnodefwv1alpha1.IngressNodeFirewallRules, 0)
	}
	inf.Spec.Ingress = append(inf.Spec.Ingress, rule)
}

func getTCPUDPRule(order uint32, protocol ingressnodefwv1alpha1.IngressNodeFirewallRuleProtocolType, ports string,
	action ingressnodefwv1alpha1.IngressNodeFirewallActionType) ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule {

	return ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
		Order:    order,
		Protocol: protocol,
		ProtocolRule: &ingressnodefwv1alpha1.IngressNodeFirewallProtoRule{
			Ports: ports,
		},
		Action: action,
	}
}

func getICMPRule(order uint32, protocol ingressnodefwv1alpha1.IngressNodeFirewallRuleProtocolType, icmpType, icmpCode uint8,
	action ingressnodefwv1alpha1.IngressNodeFirewallActionType) ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule {

	return ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
		Order:    order,
		Protocol: protocol,
		ICMPRule: &ingressnodefwv1alpha1.IngressNodeFirewallICMPRule{
			ICMPType: icmpType,
			ICMPCode: icmpCode,
		},
		Action: action,
	}
}
