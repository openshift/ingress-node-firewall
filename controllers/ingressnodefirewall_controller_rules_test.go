package controllers

import (
	"context"
	"fmt"
	"strings"
	"time"

	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var _ = Describe("IngressNodeFirewall controller rules", func() {

	const (
		timeout     = time.Second * 10
		interval    = time.Millisecond * 250
		worker0Name = "worker-0"
	)

	ctx := context.Background()

	BeforeEach(func() {
		nodes := []v1.Node{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: worker0Name,
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

	tcs := map[string]struct {
		inSpecs     []infv1alpha1.IngressNodeFirewallSpec
		outSpec     infv1alpha1.IngressNodeFirewallNodeStateSpec
		statusError string
	}{
		"baseline test without merging": {
			inSpecs: []infv1alpha1.IngressNodeFirewallSpec{
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
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
					},
					Interfaces: []string{"eth0"},
				},
			},
			outSpec: infv1alpha1.IngressNodeFirewallNodeStateSpec{
				InterfaceIngressRules: map[string][]infv1alpha1.IngressNodeFirewallRules{
					"eth0": {
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
					},
				},
			},
		},
		"duplicate rules and interfaces shall throw an error due to duplicate order": {
			inSpecs: []infv1alpha1.IngressNodeFirewallSpec{
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
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
					},
					Interfaces: []string{"eth0"},
				},
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
						{
							SourceCIDRs: []string{"10.0.0.0"},
							FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 10, // should throw error
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
					Interfaces: []string{"eth0"},
				},
			},
			outSpec:     infv1alpha1.IngressNodeFirewallNodeStateSpec{},
			statusError: "duplicate order 10 detected",
		},
		"simple merge test": {
			inSpecs: []infv1alpha1.IngressNodeFirewallSpec{
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
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
					},
					Interfaces: []string{"eth0"},
				},
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
						{
							SourceCIDRs: []string{"10.0.1.0"},
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
					Interfaces: []string{"eth1"},
				},
			},
			outSpec: infv1alpha1.IngressNodeFirewallNodeStateSpec{
				InterfaceIngressRules: map[string][]infv1alpha1.IngressNodeFirewallRules{
					"eth0": {
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
					},
					"eth1": {
						{
							SourceCIDRs: []string{"10.0.1.0"},
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
		},
		"merging rules for the same interface, CIDR, protocol and order - different port": {
			inSpecs: []infv1alpha1.IngressNodeFirewallSpec{
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
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
					},
					Interfaces: []string{"eth0"},
				},
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
						{
							SourceCIDRs: []string{"10.0.0.0"},
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
					Interfaces: []string{"eth0"},
				},
			},
			outSpec:     infv1alpha1.IngressNodeFirewallNodeStateSpec{},
			statusError: "duplicate order 10 detected",
		},
		"merging rules for the same interface, CIDR, order - different different protocol": {
			inSpecs: []infv1alpha1.IngressNodeFirewallSpec{
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
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
					},
					Interfaces: []string{"eth0"},
				},
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
						{
							SourceCIDRs: []string{"10.0.0.0"},
							FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 10,
									ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
										Protocol: infv1alpha1.ProtocolTypeUDP,
										TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
											Ports: intstr.FromInt(80),
										},
									},
									Action: infv1alpha1.IngressNodeFirewallAllow,
								},
							},
						},
					},
					Interfaces: []string{"eth0"},
				},
			},
			outSpec:     infv1alpha1.IngressNodeFirewallNodeStateSpec{},
			statusError: "duplicate order 10 detected",
		},
		"merging rules for the same interface, CIDR, protocol, port and order - different action": {
			inSpecs: []infv1alpha1.IngressNodeFirewallSpec{
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
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
					},
					Interfaces: []string{"eth0"},
				},
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
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
									Action: infv1alpha1.IngressNodeFirewallDeny,
								},
							},
						},
					},
					Interfaces: []string{"eth0"},
				},
			},
			outSpec:     infv1alpha1.IngressNodeFirewallNodeStateSpec{},
			statusError: "duplicate order 10 detected",
		},
		"merging rules for the same interface, CIDR, protocol, port - different action and order": {
			inSpecs: []infv1alpha1.IngressNodeFirewallSpec{
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
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
					},
					Interfaces: []string{"eth0"},
				},
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
						{
							SourceCIDRs: []string{"10.0.0.0"},
							FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 20,
									ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
										Protocol: infv1alpha1.ProtocolTypeTCP,
										TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
											Ports: intstr.FromInt(88),
										},
									},
									Action: infv1alpha1.IngressNodeFirewallDeny,
								},
							},
						},
					},
					Interfaces: []string{"eth0"},
				},
			},
			outSpec: infv1alpha1.IngressNodeFirewallNodeStateSpec{
				InterfaceIngressRules: map[string][]infv1alpha1.IngressNodeFirewallRules{
					"eth0": {
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
								{
									Order: 20,
									ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
										Protocol: infv1alpha1.ProtocolTypeTCP,
										TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
											Ports: intstr.FromInt(88),
										},
									},
									Action: infv1alpha1.IngressNodeFirewallDeny,
								},
							},
						},
					},
				},
			},
		},
		"merging rules for the same interface, different CIDR, protocol, port": {
			inSpecs: []infv1alpha1.IngressNodeFirewallSpec{
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
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
					},
					Interfaces: []string{"eth0"},
				},
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
						{
							SourceCIDRs: []string{"10.0.1.0"},
							FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 10,
									ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
										Protocol: infv1alpha1.ProtocolTypeTCP,
										TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
											Ports: intstr.FromInt(81),
										},
									},
									Action: infv1alpha1.IngressNodeFirewallDeny,
								},
							},
						},
					},
					Interfaces: []string{"eth0"},
				},
			},
			outSpec: infv1alpha1.IngressNodeFirewallNodeStateSpec{
				InterfaceIngressRules: map[string][]infv1alpha1.IngressNodeFirewallRules{
					"eth0": {
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
						{
							SourceCIDRs: []string{"10.0.1.0"},
							FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 10,
									ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
										Protocol: infv1alpha1.ProtocolTypeTCP,
										TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
											Ports: intstr.FromInt(81),
										},
									},
									Action: infv1alpha1.IngressNodeFirewallDeny,
								},
							},
						},
					},
				},
			},
		},
		"merging rules with multiple CIDRs": {
			inSpecs: []infv1alpha1.IngressNodeFirewallSpec{
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
						{
							SourceCIDRs: []string{"10.0.0.0", "10.0.1.0"},
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
					Interfaces: []string{"eth0"},
				},
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
						{
							SourceCIDRs: []string{"10.0.0.0", "10.0.1.0"},
							FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 20,
									ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
										Protocol: infv1alpha1.ProtocolTypeTCP,
										TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
											Ports: intstr.FromInt(81),
										},
									},
									Action: infv1alpha1.IngressNodeFirewallDeny,
								},
							},
						},
					},
					Interfaces: []string{"eth0"},
				},
			},
			outSpec: infv1alpha1.IngressNodeFirewallNodeStateSpec{
				InterfaceIngressRules: map[string][]infv1alpha1.IngressNodeFirewallRules{
					"eth0": {
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
								{
									Order: 20,
									ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
										Protocol: infv1alpha1.ProtocolTypeTCP,
										TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
											Ports: intstr.FromInt(81),
										},
									},
									Action: infv1alpha1.IngressNodeFirewallDeny,
								},
							},
						},
						{
							SourceCIDRs: []string{"10.0.1.0"},
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
								{
									Order: 20,
									ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
										Protocol: infv1alpha1.ProtocolTypeTCP,
										TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
											Ports: intstr.FromInt(81),
										},
									},
									Action: infv1alpha1.IngressNodeFirewallDeny,
								},
							},
						},
					},
				},
			},
		},
		"complex merge test": {
			inSpecs: []infv1alpha1.IngressNodeFirewallSpec{
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
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
					},
					Interfaces: []string{"eth0"},
				},
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
						{
							SourceCIDRs: []string{"10.0.1.0"},
							FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 20,
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
					Interfaces: []string{"eth1"},
				},
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
						{
							SourceCIDRs: []string{"10.0.2.0"},
							FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 30,
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
					Interfaces: []string{"eth0"},
				},
			},
			outSpec: infv1alpha1.IngressNodeFirewallNodeStateSpec{
				InterfaceIngressRules: map[string][]infv1alpha1.IngressNodeFirewallRules{
					"eth0": {
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
						{
							SourceCIDRs: []string{"10.0.2.0"},
							FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 30,
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
					"eth1": {
						{
							SourceCIDRs: []string{"10.0.1.0"},
							FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 20,
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
		},
		"invalid interface name test": {
			inSpecs: []infv1alpha1.IngressNodeFirewallSpec{
				{
					Ingress: []infv1alpha1.IngressNodeFirewallRules{
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
					},
					Interfaces: []string{},
				},
			},
			outSpec:     infv1alpha1.IngressNodeFirewallNodeStateSpec{},
			statusError: "Invalid interface name",
		},
	}

	for s, tc := range tcs {
		// Deal with the typical golang for range issue by reassigning to a new variable.
		tc := tc
		When(fmt.Sprintf("IngressNodeFirewall objects are created for test case: %q", s), func() {
			It("The resulting IngressNodeFirewallNodeState object should look as expected", func() {
				By("Creating new IngressNodeFirewall objects")
				for k, spec := range tc.inSpecs {
					objectName := fmt.Sprintf("firewall-%d", k)
					fmt.Fprintf(GinkgoWriter, "By creating new IngressNodeFirewall object %s", objectName)
					ingressNodeFirewall := infv1alpha1.IngressNodeFirewall{
						TypeMeta:   metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{Name: objectName},
						Spec:       spec,
						Status: infv1alpha1.IngressNodeFirewallStatus{
							SyncStatus: infv1alpha1.FirewallRulesSyncOK,
						},
					}
					Expect(k8sClient.Create(ctx, &ingressNodeFirewall)).Should(Succeed())
				}

				// Define the NodeState object that will hold the state and the lookup key.
				infns := &infv1alpha1.IngressNodeFirewallNodeState{}
				key := types.NamespacedName{Namespace: IngressNodeFwConfigTestNameSpace, Name: worker0Name}

				if tc.statusError == "" {
					By("Waiting for the expected list of IngressNodeFirewallNodeStates")
					hasIngressNodeFirewallNodeStates(ctx, k8sClient, []string{worker0Name})

					Eventually(func() bool {
						By("Making sure that the resource displays a successful synchronization status")
						// Refresh the resource.
						if err := k8sClient.Get(ctx, key, infns); err != nil {
							fmt.Fprintf(GinkgoWriter, "Getting resource failed: %q\n", err)
							return false
						}
						// Compare synchronization status.
						if infns.Status.SyncStatus != infv1alpha1.SyncOK {
							fmt.Fprintf(GinkgoWriter,
								"SyncStatus does not match SyncOK, instead got: %q\n", infns.Status.SyncStatus)
							return false
						}

						By("Comparing the generated IngressNodeFirewallNodeStateSpec to the expected " +
							"IngressNodeFirewallNodeStateSpec")
						// Compare the Specs.
						ingressesEqual := equality.Semantic.DeepEqual(
							infns.Spec.InterfaceIngressRules, tc.outSpec.InterfaceIngressRules)
						if !ingressesEqual {
							fmt.Fprintf(GinkgoWriter, "Ingresses do not match. Got: '%v', Expected '%v'\n",
								infns.Spec.InterfaceIngressRules, tc.outSpec.InterfaceIngressRules)
						}
						return ingressesEqual
					}).Should(BeTrue())
				} else {
					Eventually(func() bool {
						By("Making sure that the resource displays an error synchronization status")
						// Refresh the resource.
						if err := k8sClient.Get(ctx, key, infns); err != nil {
							fmt.Fprintf(GinkgoWriter, "Getting resource failed: %q\n", err)
							return false
						}
						// Compare the synchronzition status.
						if infns.Status.SyncStatus != infv1alpha1.SyncError {
							fmt.Fprintf(GinkgoWriter,
								"SyncStatus does not match SyncError, got: %q\n", infns.Status.SyncStatus)
							return false
						}

						By("Comparing the status field's error message to the expected error message")
						// Compare the error message.
						syncErrorContains := strings.Contains(infns.Status.SyncErrorMessage, tc.statusError)
						if !syncErrorContains {
							fmt.Fprintf(GinkgoWriter, "Sync error does not contain expected string '%s'. Got: '%s'\n",
								tc.statusError, infns.Status.SyncErrorMessage)
						}
						return syncErrorContains
					}).Should(BeTrue())
				}
			})
		})
	}
})
