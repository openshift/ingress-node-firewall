package controllers

import (
	"context"
	"fmt"
	"sync"
	"time"

	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var ingressNodeFirewallRules map[string][]infv1alpha1.IngressNodeFirewallRules
var m sync.Mutex

// ebpfSingletonMock implements ebpfDaemon.
type ebpfSingletonMock struct{}

func (e *ebpfSingletonMock) SyncInterfaceIngressRules(
	ifaceIngressRules map[string][]infv1alpha1.IngressNodeFirewallRules, isDelete bool) error {
	m.Lock()
	ingressNodeFirewallRules = ifaceIngressRules
	m.Unlock()
	return nil
}

var _ = Describe("IngressNodeFirewallNodeState controller", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	// Mock the ebpfDaemon.
	mock = &ebpfSingletonMock{}
	ctx := context.TODO()

	BeforeEach(func() {
		By(fmt.Sprintf("Creating a new Node object with name %s", daemonReconcilerNodeName))
		node := v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: daemonReconcilerNodeName,
			},
		}
		Expect(k8sClient.Create(ctx, &node)).Should(Succeed())

		By(fmt.Sprintf("Creating a new IngressNodeFirewallNodeState object for node %s", daemonReconcilerNodeName))
		ingressNodeFirewall := infv1alpha1.IngressNodeFirewallNodeState{
			TypeMeta:   metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{Name: daemonReconcilerNodeName, Namespace: IngressNodeFwConfigTestNameSpace},
			Spec: infv1alpha1.IngressNodeFirewallNodeStateSpec{
				InterfaceIngressRules: map[string][]infv1alpha1.IngressNodeFirewallRules{
					"dummy0": {
						{
							SourceCIDRs: []string{"10.0.0.0/8"},
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
					},
					"dummy1": {
						{
							SourceCIDRs: []string{"10.0.1.0/8"},
							FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 10,
									ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
										Protocol: infv1alpha1.ProtocolTypeTCP,
										TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
											Ports: intstr.FromInt(81),
										},
									},
									Action: infv1alpha1.IngressNodeFirewallAllow,
								},
							},
						},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, &ingressNodeFirewall)).Should(Succeed())
	})

	AfterEach(func() {
		By("Cleaning up custom resources")
		Expect(k8sClient.DeleteAllOf(
			context.Background(),
			&infv1alpha1.IngressNodeFirewallNodeState{},
			client.InNamespace(IngressNodeFwConfigTestNameSpace))).Should(Succeed())
	})

	// TODO: These tests here are overly simple. Fill them with life.
	When(fmt.Sprintf("an IngressNodeFirewallNodeState object is created that matches node name %s", daemonReconcilerNodeName), func() {
		It(fmt.Sprintf("eBPF rule reconciliation for node %s should be triggered", daemonReconcilerNodeName), func() {
			By("Checking that the reconciler was called")
			Eventually(func() bool {
				m.Lock()
				l := len(ingressNodeFirewallRules)
				m.Unlock()
				return l == 2
			}, timeout, interval).Should(BeTrue())
		})
	})
})
