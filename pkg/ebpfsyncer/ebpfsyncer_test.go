package ebpfsyncer

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
	"testing"
	"time"

	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	nodefwloader "github.com/openshift/ingress-node-firewall/pkg/ebpf"
	intutil "github.com/openshift/ingress-node-firewall/pkg/interfaces"

	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

const (
	interfacePrefix   = "dummy"
	netnsName         = "dummy"
	testProto         = "tcp"
	testPort1         = "12345"
	testPort2         = "12346"
	numTestInterfaces = 3
)

// var originalNetNS netns.NsHandle
// var newNetNS netns.NsHandle
// var newNetNSName string
var interfaces []netlink.Veth

// TestSyncInterfaceIngressRulesWithHTTP runs an HTTP server, attaches rules to interfaces and verifies that
// the rules work.
func TestSyncInterfaceIngressRulesWithHTTP(t *testing.T) {
	checkCommandDependenciesOrSkip(t, []string{"nc"})

	defer afterEach(t)
	beforeEach(t)

	tcs := []struct {
		rules        map[string][]infv1alpha1.IngressNodeFirewallRules
		isDelete     bool
		targetResult map[string]bool // true means the connection should succeed
	}{
		// TC0 - reset back to no rules.
		{
			targetResult: map[string]bool{
				"192.0.2.1:12346": true,
				"192.0.2.5:12345": true,
				"192.0.2.5:12346": true,
				"192.0.2.1:12345": true,
			},
		},
		// TC1 - test a single rule and default drop.
		// NOTE: When a CIDR is loaded to the ruleset as part of the key, the default action for the entire source CIDR
		// will be set to DROP. That means we expect a drop when testing against 192.0.2.1:12346.
		{
			rules: map[string][]infv1alpha1.IngressNodeFirewallRules{
				fmt.Sprintf("%s0", interfacePrefix): {
					{
						SourceCIDRs: []string{"192.0.2.0/24"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallDeny,
							},
						},
					},
				},
			},
			targetResult: map[string]bool{
				"192.0.2.1:12345": false,
				"192.0.2.1:12346": true,
				"192.0.2.5:12345": true,
				"192.0.2.5:12346": true,
			},
		},
		// TC2 - open another port.
		{
			rules: map[string][]infv1alpha1.IngressNodeFirewallRules{
				fmt.Sprintf("%s0", interfacePrefix): {
					{
						SourceCIDRs: []string{"192.0.2.0/24"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallDeny,
							},
							{
								Order: 20,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort2),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
						},
					},
				},
			},
			targetResult: map[string]bool{
				"192.0.2.1:12345": false,
				"192.0.2.1:12346": true,
				"192.0.2.5:12345": true,
				"192.0.2.5:12346": true,
			},
		},
		// TC3 - reset back to no rules.
		{
			targetResult: map[string]bool{
				"192.0.2.1:12345": true,
				"192.0.2.1:12346": true,
				"192.0.2.5:12345": true,
				"192.0.2.5:12346": true,
			},
		},
		// TC4 - open both ports on dummy0 and do not attach any rules on dummy1.
		// Note: We default drop for the entire CIDR as soon as a src CIDR is attached to an interface index.
		{
			rules: map[string][]infv1alpha1.IngressNodeFirewallRules{
				fmt.Sprintf("%s0", interfacePrefix): {
					{
						SourceCIDRs: []string{"192.0.2.0/24"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
							{
								Order: 20,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort2),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
						},
					},
				},
			},
			targetResult: map[string]bool{
				"192.0.2.1:12345": true,
				"192.0.2.1:12346": true,
				"192.0.2.5:12345": true,
				"192.0.2.5:12346": true,
			},
		},
		// TC5 - reset back to no rules.
		{
			targetResult: map[string]bool{
				"192.0.2.1:12346": true,
				"192.0.2.5:12345": true,
				"192.0.2.5:12346": true,
				"192.0.2.1:12345": true,
			},
		},
		// TC5
		{
			rules: map[string][]infv1alpha1.IngressNodeFirewallRules{
				fmt.Sprintf("%s0", interfacePrefix): {
					{
						SourceCIDRs: []string{"192.0.2.0/24"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallDeny,
							},
							{
								Order: 20,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort2),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
						},
					},
				},
				fmt.Sprintf("%s1", interfacePrefix): {
					{
						SourceCIDRs: []string{"192.0.2.0/24"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
							{
								Order: 20,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort2),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallDeny,
							},
						},
					},
				},
			},
			targetResult: map[string]bool{
				"192.0.2.1:12345": false,
				"192.0.2.1:12346": true,
				"192.0.2.5:12345": true,
				"192.0.2.5:12346": false,
			},
		},
		// TC6 - delete object.
		{
			isDelete: true,
			targetResult: map[string]bool{
				"192.0.2.1:12346": true,
				"192.0.2.5:12345": true,
				"192.0.2.5:12346": true,
				"192.0.2.1:12345": true,
			},
		},
		// TC7 - test with no rules.
		{
			targetResult: map[string]bool{
				"192.0.2.1:12346": true,
				"192.0.2.5:12345": true,
				"192.0.2.5:12346": true,
				"192.0.2.1:12345": true,
			},
		},
		// TC8
		{
			rules: map[string][]infv1alpha1.IngressNodeFirewallRules{
				fmt.Sprintf("%s0", interfacePrefix): {
					{
						SourceCIDRs: []string{"192.0.2.0/30"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallDeny,
							},
							{
								Order: 20,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort2),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
						},
					},
				},
				fmt.Sprintf("%s1", interfacePrefix): {
					{
						SourceCIDRs: []string{"192.0.2.4/30"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
							{
								Order: 20,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort2),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallDeny,
							},
						},
					},
				},
			},
			targetResult: map[string]bool{
				"192.0.2.1:12345": false,
				"192.0.2.1:12346": true,
				"192.0.2.5:12345": true,
				"192.0.2.5:12346": false,
			},
		},
		// TC9
		{
			rules: map[string][]infv1alpha1.IngressNodeFirewallRules{
				fmt.Sprintf("%s0", interfacePrefix): {
					{
						SourceCIDRs: []string{"192.0.2.0/30"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
							{
								Order: 20,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort2),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallDeny,
							},
						},
					},
				},
				fmt.Sprintf("%s1", interfacePrefix): {
					{
						SourceCIDRs: []string{"192.0.2.4/30"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallDeny,
							},
							{
								Order: 20,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort2),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
						},
					},
				},
			},
			targetResult: map[string]bool{
				"192.0.2.1:12345": true,
				"192.0.2.1:12346": false,
				"192.0.2.5:12345": false,
				"192.0.2.5:12346": true,
			},
		},
	}

	ctx := context.Background()
	t.Log("Running a server that's listening on", testProto, testPort1)
	go func() {
		err := runListenServer(ctx, testProto, testPort1)
		if err != nil {
			panic(err)
		}
	}()
	t.Log("Running a server that's listening on", testProto, testPort2)
	go func() {
		err := runListenServer(ctx, testProto, testPort2)
		if err != nil {
			panic(err)
		}
	}()

	t.Log("Giving the server a few seconds to start")
	time.Sleep(2 * time.Second)

	l := zap.New()

	for i, tc := range tcs {
		t.Log("Running the ebpfsyncer's sync to update rules")
		err := GetEbpfSyncer(ctx, l, nil, nil, nil).SyncInterfaceIngressRules(tc.rules, tc.isDelete)
		if err != nil {
			t.Fatal(err)
		}

		t.Log("Waiting a little")
		time.Sleep(2 * time.Second)

		for target, result := range tc.targetResult {
			ipPort := strings.Split(target, ":")
			t.Logf("TestSyncInterfaceIngressRulesWithHTTP(%d): Trying to connect to %s (success should be %t)",
				i, target, result)
			err := testTCP(ipPort[0], ipPort[1])
			if result && err != nil || !result && err == nil {
				t.Fatalf("TestSyncInterfaceIngressRulesWithHTTP(%d): Connection to %s should be %t but instead we saw %v",
					i, target, result, err)
			}
		}
	}
}

// TestSyncInterfaceIngressRulesAttachAndDetachSingleInterface attaches and detaches rules from interfaces 2x in a row
// to test that this operation works. It does not check if keys or rules are created correctly. Instead see
// TestVerifyBPFKeysAfterInterfaceIngressRulesUpdate.
func TestSyncInterfaceIngressRulesAttachAndDetachSingleInterface(t *testing.T) {
	defer afterEach(t)
	beforeEach(t)
	rules := map[string][]infv1alpha1.IngressNodeFirewallRules{
		fmt.Sprintf("%s0", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.0.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
							Protocol: infv1alpha1.ProtocolTypeTCP,
							TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
								Ports: intstr.FromString(testPort1),
							},
						},
						Action: infv1alpha1.IngressNodeFirewallAllow,
					},
				},
			},
			{
				SourceCIDRs: []string{"0.0.0.0/0"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
							Protocol: infv1alpha1.ProtocolTypeTCP,
							TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
								Ports: intstr.FromString(testPort1),
							},
						},
						Action: infv1alpha1.IngressNodeFirewallDeny,
					},
				},
			},
		},
	}

	ctx := context.Background()
	l := zap.New()
	t.Log("Running the ebpfsyncer's sync to attach rules")
	err := GetEbpfSyncer(ctx, l, nil, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Running ebpfsyncer's sync to delete rules")
	err = GetEbpfSyncer(ctx, l, nil, nil, nil).SyncInterfaceIngressRules(rules, true)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Running the ebpfsyncer's sync to attach rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Running ebpfsyncer's sync to delete rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil, nil).SyncInterfaceIngressRules(rules, true)
	if err != nil {
		t.Fatal(err)
	}
}

// TestSyncInterfaceIngressRulesAttachAndDetachMultiInterface attaches and detaches rules from interfaces 2x in a row
// to test that this operation works. It does not check if keys or rules are created correctly. Instead see
// TestVerifyBPFKeysAfterInterfaceIngressRulesUpdate.
func TestSyncInterfaceIngressRulesAttachAndDetachMultiInterface(t *testing.T) {
	defer afterEach(t)
	beforeEach(t)
	rules := map[string][]infv1alpha1.IngressNodeFirewallRules{
		fmt.Sprintf("%s0", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.0.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
							Protocol: infv1alpha1.ProtocolTypeTCP,
							TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
								Ports: intstr.FromString(testPort1),
							},
						},
						Action: infv1alpha1.IngressNodeFirewallAllow,
					},
				},
			},
		},
		fmt.Sprintf("%s1", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.1.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
							Protocol: infv1alpha1.ProtocolTypeTCP,
							TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
								Ports: intstr.FromString(testPort1),
							},
						},
						Action: infv1alpha1.IngressNodeFirewallAllow,
					},
				},
			},
		},
		fmt.Sprintf("%s2", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.2.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
							Protocol: infv1alpha1.ProtocolTypeTCP,
							TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
								Ports: intstr.FromString(testPort1),
							},
						},
						Action: infv1alpha1.IngressNodeFirewallAllow,
					},
				},
			},
		},
	}

	ctx := context.Background()
	l := zap.New()
	t.Log("Running the ebpfsyncer's sync to attach rules")
	err := GetEbpfSyncer(ctx, l, nil, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Running ebpfsyncer's sync to delete rules")
	err = GetEbpfSyncer(ctx, l, nil, nil, nil).SyncInterfaceIngressRules(rules, true)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Running the ebpfsyncer's sync to attach rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Running ebpfsyncer's sync to delete rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil, nil).SyncInterfaceIngressRules(rules, true)
	if err != nil {
		t.Fatal(err)
	}
}

// TestResyncInterfaceIngressRules calls the rule attach twice in a row to test idempotency with a single interface.
func TestResyncInterfaceIngressRulesSingleInterface(t *testing.T) {
	defer afterEach(t)
	beforeEach(t)
	rules := map[string][]infv1alpha1.IngressNodeFirewallRules{
		fmt.Sprintf("%s0", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.0.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
							Protocol: infv1alpha1.ProtocolTypeTCP,
							TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
								Ports: intstr.FromString(testPort1),
							},
						},
						Action: infv1alpha1.IngressNodeFirewallAllow,
					},
				},
			},
			{
				SourceCIDRs: []string{"0.0.0.0/0"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
							Protocol: infv1alpha1.ProtocolTypeTCP,
							TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
								Ports: intstr.FromString(testPort1),
							},
						},
						Action: infv1alpha1.IngressNodeFirewallDeny,
					},
				},
			},
		},
	}

	ctx := context.Background()
	t.Log("Running the ebpfsyncer's sync to attach rules")
	l := zap.New()
	err := GetEbpfSyncer(ctx, l, nil, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Running the ebpfsyncer's sync to attach rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}
}

// TestResyncInterfaceIngressRulesMultiInterface calls the rule attach twice in a row to test idempotency with
// 2 different interfaces to attach to.
func TestResyncInterfaceIngressRulesMultiInterface(t *testing.T) {
	defer afterEach(t)
	beforeEach(t)
	rules := map[string][]infv1alpha1.IngressNodeFirewallRules{
		fmt.Sprintf("%s0", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.0.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
							Protocol: infv1alpha1.ProtocolTypeTCP,
							TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
								Ports: intstr.FromString(testPort1),
							},
						},
						Action: infv1alpha1.IngressNodeFirewallAllow,
					},
				},
			},
		},
		fmt.Sprintf("%s1", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.1.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
							Protocol: infv1alpha1.ProtocolTypeTCP,
							TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
								Ports: intstr.FromString(testPort1),
							},
						},
						Action: infv1alpha1.IngressNodeFirewallAllow,
					},
				},
			},
		},
		fmt.Sprintf("%s2", interfacePrefix): {
			{
				SourceCIDRs: []string{"10.0.2.0/16"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
							Protocol: infv1alpha1.ProtocolTypeTCP,
							TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
								Ports: intstr.FromString(testPort1),
							},
						},
						Action: infv1alpha1.IngressNodeFirewallAllow,
					},
				},
			},
		},
	}

	ctx := context.Background()
	t.Log("Running the ebpfsyncer's sync to attach rules")
	l := zap.New()
	err := GetEbpfSyncer(ctx, l, nil, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatalf("Failed attach operation, err: %q", err)
	}

	t.Log("Running the ebpfsyncer's sync to attach rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatalf("Failed attach operation, err: %q", err)
	}
}

// TestVerifyBPFKeysAfterInterfaceIngressRulesUpdate calls the rule attach several times in a row and
// checks after each call that the keys in the BPF map match the expected keys.
func TestVerifyBPFKeysAfterInterfaceIngressRulesUpdate(t *testing.T) {
	defer afterEach(t)
	beforeEach(t)

	// Get interface indexes for dummy0 and dummy1.
	if0Index, err := intutil.GetInterfaceIndex(fmt.Sprintf("%s0", interfacePrefix))
	if err != nil {
		t.Fatal(err)
	}
	if1Index, err := intutil.GetInterfaceIndex(fmt.Sprintf("%s1", interfacePrefix))
	if err != nil {
		t.Fatal(err)
	}
	// Get eBPF keys for dummy0 and dummy1 and the type A network as well as the default network.
	ebpfKeyIf0TypeA, _ := nodefwloader.BuildEBPFKey(if0Index, "10.0.0.0/8")
	ebpfKeyIf0Default, _ := nodefwloader.BuildEBPFKey(if0Index, "0.0.0.0/0")
	ebpfKeyIf1TypeA, _ := nodefwloader.BuildEBPFKey(if1Index, "10.0.0.0/8")
	ebpfKeyIf1Default, _ := nodefwloader.BuildEBPFKey(if1Index, "0.0.0.0/0")

	// Define test cases.
	tcs := []struct {
		expectedKeys []nodefwloader.BpfLpmIpKeySt
		isDelete     bool
		rules        map[string][]infv1alpha1.IngressNodeFirewallRules
	}{
		// TC0 - 2 CIDRs on the same interface with 2 different ports on interface 0.
		{
			expectedKeys: []nodefwloader.BpfLpmIpKeySt{
				ebpfKeyIf0TypeA, ebpfKeyIf0Default,
			},
			rules: map[string][]infv1alpha1.IngressNodeFirewallRules{
				fmt.Sprintf("%s0", interfacePrefix): {
					{
						SourceCIDRs: []string{"10.0.0.0/8"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
						},
					},
					{
						SourceCIDRs: []string{"0.0.0.0/0"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallDeny,
							},
						},
					},
				},
			},
		},
		// TC1 - delete the object.
		{
			expectedKeys: []nodefwloader.BpfLpmIpKeySt{},
			isDelete:     true,
		},
		// TC2 - add all rules to interface 1.
		{
			expectedKeys: []nodefwloader.BpfLpmIpKeySt{
				ebpfKeyIf1TypeA, ebpfKeyIf1Default,
			},
			rules: map[string][]infv1alpha1.IngressNodeFirewallRules{
				fmt.Sprintf("%s1", interfacePrefix): {
					{
						SourceCIDRs: []string{"10.0.0.0/8"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
						},
					},
					{
						SourceCIDRs: []string{"0.0.0.0/0"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallDeny,
							},
						},
					},
				},
			},
		},
		// TC3 remove rules for default.
		{
			expectedKeys: []nodefwloader.BpfLpmIpKeySt{
				ebpfKeyIf1TypeA,
			},
			rules: map[string][]infv1alpha1.IngressNodeFirewallRules{
				fmt.Sprintf("%s1", interfacePrefix): {
					{
						SourceCIDRs: []string{"10.0.0.0/8"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
						},
					},
				},
			},
		},
		// TC4 - remove rules from interface 1, add rules to interface 0 with 2 CIDRs.
		{
			expectedKeys: []nodefwloader.BpfLpmIpKeySt{
				ebpfKeyIf0TypeA, ebpfKeyIf0Default,
			},
			rules: map[string][]infv1alpha1.IngressNodeFirewallRules{
				fmt.Sprintf("%s0", interfacePrefix): {
					{
						SourceCIDRs: []string{"10.0.0.0/8", "0.0.0.0/0"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
						},
					},
				},
			},
		},
		// TC5 - set interfaces to empty.
		{
			expectedKeys: []nodefwloader.BpfLpmIpKeySt{},
			rules:        map[string][]infv1alpha1.IngressNodeFirewallRules{},
		},
		// TC6 - the same CIDR on 2 different interfaces.
		{
			expectedKeys: []nodefwloader.BpfLpmIpKeySt{
				ebpfKeyIf0TypeA, ebpfKeyIf1TypeA,
			},
			rules: map[string][]infv1alpha1.IngressNodeFirewallRules{
				fmt.Sprintf("%s0", interfacePrefix): {
					{
						SourceCIDRs: []string{"10.0.0.0/8"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallDeny,
							},
							{
								Order: 20,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort2),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
						},
					},
				},
				fmt.Sprintf("%s1", interfacePrefix): {
					{
						SourceCIDRs: []string{"10.0.0.0/8"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
							{
								Order: 20,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort2),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallDeny,
							},
						},
					},
				},
			},
		},
	}

	ctx := context.Background()

	// Run each test case and compare the generated rule keys with the expected rule keys.
	for i, tc := range tcs {
		t.Logf("TestVerifyBPFKeysAfterInterfaceIngressRulesUpdate(%d): Running the ebpfsyncer's sync to attach rules", i)
		l := zap.New()
		err := GetEbpfSyncer(ctx, l, nil, nil, nil).SyncInterfaceIngressRules(tc.rules, tc.isDelete)
		if err != nil {
			t.Fatal(err)
		}

		ebpfRules, err := GetEbpfSyncer(ctx, l, nil, nil, nil).(*ebpfSingleton).getBPFMapContentForTest()
		if err != nil {
			// FIXME: This must be improved for tests with isDelete as we currently only check that the
			// map is set to nil but with the current test methodology we aren't verifying that the map is gone.
			if !(tc.isDelete && strings.Contains(err.Error(), "Nil pointer to node firewall loader")) {
				t.Fatalf("TestVerifyBPFKeysAfterInterfaceIngressRulesUpdate(%d): Could not get eBPF map content, err: %q", i, err)
			}
		}
		if len(ebpfRules) != len(tc.expectedKeys) {
			t.Fatalf("TestVerifyBPFKeysAfterInterfaceIngressRulesUpdate(%d): Unexpected result. Expected keys are %v but got %v",
				i, tc.expectedKeys, ebpfRules)
		}
		for _, expectedKey := range tc.expectedKeys {
			if _, ok := ebpfRules[expectedKey]; !ok {
				t.Fatalf("TestVerifyBPFKeysAfterInterfaceIngressRulesUpdate(%d): Could not find expected key %v in result %v",
					i, expectedKey, ebpfRules)
			}
		}
	}
}

// TestInterfaceAttachments simulates several scenarios and verifies interface attachment after these scenarios
// happened and a reconcile was called.
func TestInterfaceAttachments(t *testing.T) {
	defer afterEach(t)
	beforeEach(t)

	// Define test cases.
	tcs := []struct {
		expectedInterfaces map[string]struct{}
		isDelete           bool
		rules              map[string][]infv1alpha1.IngressNodeFirewallRules
		beforeFunc         func()
	}{
		// TC0
		{
			expectedInterfaces: map[string]struct{}{
				fmt.Sprintf("%s0", interfacePrefix): {},
				fmt.Sprintf("%s1", interfacePrefix): {},
			},
			rules: map[string][]infv1alpha1.IngressNodeFirewallRules{
				fmt.Sprintf("%s0", interfacePrefix): {
					{
						SourceCIDRs: []string{"10.0.0.0/8"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
						},
					},
				},
				fmt.Sprintf("%s1", interfacePrefix): {
					{
						SourceCIDRs: []string{"10.0.0.0/8"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
						},
					},
				},
			},
		},
		// TC1 - simulate a process restart / crash.
		{
			beforeFunc: func() {
				once = sync.Once{}
				instance = nil
			},
			expectedInterfaces: map[string]struct{}{
				fmt.Sprintf("%s0", interfacePrefix): {},
				fmt.Sprintf("%s1", interfacePrefix): {},
			},
			rules: map[string][]infv1alpha1.IngressNodeFirewallRules{
				fmt.Sprintf("%s0", interfacePrefix): {
					{
						SourceCIDRs: []string{"10.0.0.0/8"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
						},
					},
				},
				fmt.Sprintf("%s1", interfacePrefix): {
					{
						SourceCIDRs: []string{"10.0.0.0/8"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
						},
					},
				},
			},
		},
		// TC2 - simulate interface detachment.
		// FIXME: I suspect that there's a bug with detach operations for veth interfaces. I see this here flake
		// on my virtual machine regardless of the sleep, but with a 2 second sleep it does at least pass from time
		// to time. Further testing is needed to see if this only affects veth interfaces or if other interface
		// types might be affected by this, too. As things currently stand, the following operation reports success
		// '"Running detach operation for interface","intf":"dummy1' but when deleting the pin and closing the FD,
		// the XDP hook is still attached and stale and it cannot be disconnected (the device reports busy forever).
		// Maybe it's just a kernel bug with veth ...
		/*{
			beforeFunc: func() {
				// once = sync.Once{}
				// instance = nil
			},
			expectedInterfaces: map[string]struct{}{
				fmt.Sprintf("%s0", interfacePrefix): {},
			},
			rules: map[string][]infv1alpha1.IngressNodeFirewallRules{
				fmt.Sprintf("%s0", interfacePrefix): {
					{
						SourceCIDRs: []string{"10.0.0.0/8"},
						FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
							{
								Order: 10,
								ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
									Protocol: infv1alpha1.ProtocolTypeTCP,
									TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
										Ports: intstr.FromString(testPort1),
									},
								},
								Action: infv1alpha1.IngressNodeFirewallAllow,
							},
						},
					},
				},
			},
		},*/
		// TC3 - simulate deletion - should trigger interface detachment.
		// FIXME: Same as TC2. The interface says it's busy and it cannot be detached and the test fails.
		/*{
			expectedInterfaces: map[string]struct{}{},
			isDelete:           true,
		},*/
	}

	ctx := context.Background()
	l := zap.New()

	// Run each test case and compare the generates rule keys with the expected rule keys.
	for i, tc := range tcs {
		if tc.beforeFunc != nil {
			t.Logf("TestInterfaceAttachments(%d): Running the beforeFunc()", i)
			tc.beforeFunc()
		}

		t.Logf("TestInterfaceAttachments(%d): Running the ebpfsyncer's sync to attach rules to interfaces", i)
		err := GetEbpfSyncer(ctx, l, nil, nil, nil).SyncInterfaceIngressRules(tc.rules, tc.isDelete)
		if err != nil {
			t.Fatalf("TestInterfaceAttachments(%d): SyncInterfaceIngressRules returned an error, err: %q", i, err)
		}

		t.Logf("TestInterfaceAttachments(%d): Sleeping for 2 seconds to give any detach/attach operations time to finish", i)
		time.Sleep(2 * time.Second)

		interfaces, err := intutil.GetInterfacesWithXDPAttached()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("TestInterfaceAttachments(%d): Found the following interfaces on this system with XDP attached %v",
			i, interfaces)

		if len(interfaces) != len(tc.expectedInterfaces) {
			t.Fatalf("TestInterfaceAttachments(%d): Unexpected result. Expected interfaces are %v but got %v",
				i, tc.expectedInterfaces, interfaces)
		}
		for _, foundInterface := range interfaces {
			if _, ok := tc.expectedInterfaces[foundInterface]; !ok {
				t.Fatalf("TestInterfaceAttachments(%d): Could not find found interface %v in expected list %v",
					i, foundInterface, tc.expectedInterfaces)
			}
		}
	}
}

func runListenServer(ctx context.Context, protocol, port string) error {
	ln, err := net.Listen(protocol, fmt.Sprintf(":%s", port))
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			_, err := io.WriteString(c, time.Now().Format("15:04:05\n"))
			if err != nil {
				return // e.g., client disconnected
			}
		}(conn)
	}
}

func testTCP(ip, port string) error {
	cmd := exec.Command("ip", "netns", "exec", netnsName, "nc", "-w", "2", "-z", ip, port)
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func cleanup(t *testing.T) {
	t.Log("Deleting all XDP pins")
	err := os.RemoveAll("/sys/fs/bpf/xdp_ingress_node_firewall_process")
	if err != nil {
		t.Log(err)
	}

	t.Log("Deleting the test interfaces")
	for i := range interfaces {
		err = netlink.LinkDel(&interfaces[i])
		if err != nil {
			t.Log(err)
		}
	}

	t.Log("Deleting the netns")
	cmd := exec.Command("ip", "netns", "del", netnsName)
	if err := cmd.Run(); err != nil {
		t.Log(err)
	}

	// Reset once to simulate a complete restart of the process. Without this reset, we would run into issues due
	// to the interface and directory resets that we do on cleanup.
	once = sync.Once{}
}

func beforeEach(t *testing.T) {
	// First, check if the user is root; skip otherwise.
	t.Log("Checking if this test runs with sufficiently high privileges")
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("Unable to get current user: %s", err)
	}
	if currentUser.Uid != "0" {
		t.Skipf("Skipping this test due to insufficient privileges")
	}

	// By setting isValidInterfaceNameAndState to a mock.
	isValidInterfaceNameAndState = func(ifName string) bool {
		return true
	}

	// Generate test interfaces and populate the slice. Then, run the cleanup (that way, we can delete the interfaces
	// if they already exist).
	t.Log("By populating the interface list")
	interfaces = []netlink.Veth{}
	for i := 0; i < numTestInterfaces; i++ {
		// Create interface.
		la := netlink.NewLinkAttrs()
		la.Name = fmt.Sprintf("%s%d", interfacePrefix, i)
		tap := netlink.Veth{
			LinkAttrs: la,
			PeerName:  fmt.Sprintf("%s-peer", la.Name),
		}
		interfaces = append(interfaces, tap)
	}

	// Run a cleanup, just in case (cleanup will only log failures to clean up, it will not fail).
	t.Log("By running a cleanup")
	cleanup(t)

	t.Log("By creating the namespace")
	cmd := exec.Command("ip", "netns", "add", netnsName)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("ip", "netns", "exec", netnsName, "ip", "link", "set", "dev", "lo", "up")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}

	// Now, actually create the interfaces.
	t.Log("By creating new test interfaces for testing")
	for i, tap := range interfaces {
		err = netlink.LinkAdd(&tap)
		if err != nil {
			t.Fatalf("Could not add link %s, err: %q", tap.Name, err)
		}
		err = netlink.LinkSetUp(&tap)
		if err != nil {
			t.Fatalf("Could not set link state to up for link %s, err: %q", tap.Name, err)
		}

		// Assign 192.0.2.x+1/32 to dummyx, and so on.
		addr0, err := netlink.ParseAddr(fmt.Sprintf("192.0.2.%d/30", i*4+1))
		if err != nil {
			t.Fatalf("Could not parse IP address, err: %q", err)
		}
		err = netlink.AddrAdd(&tap, addr0)
		if err != nil {
			t.Fatalf("Could not add IP address to interface, err: %q", err)
		}

		t.Log("By moving the peer interfaces to their own namespace and by assigning an IP")
		cmd := exec.Command("ip", "link", "set", "dev", interfaces[i].PeerName, "netns", netnsName)
		if err := cmd.Run(); err != nil {
			t.Fatalf("Could not set netns for %s, err: %q", interfaces[i].PeerName, err)
		}
		cmd = exec.Command("ip", "netns", "exec", netnsName, "ip", "address", "add", "dev", interfaces[i].PeerName, fmt.Sprintf("192.0.2.%d/30", i*4+2))
		if err := cmd.Run(); err != nil {
			t.Fatalf("Could not add IP address to interface %s in netns %s, err: %q", interfaces[i].PeerName, netnsName, err)
		}
		cmd = exec.Command("ip", "netns", "exec", netnsName, "ip", "link", "set", "dev", interfaces[i].PeerName, "up")
		if err := cmd.Run(); err != nil {
			t.Fatalf("Could not set link to up in netns %s, link %s, err: %q", interfaces[i].PeerName, netnsName, err)
		}
	}
}

func afterEach(t *testing.T) {
	if t.Skipped() {
		return
	}
	cleanup(t)
}

func checkCommandDependenciesOrSkip(t *testing.T, cmdList []string) {
	for _, cmd := range cmdList {
		_, err := exec.LookPath(cmd)
		if err != nil {
			t.Skipf("Skipping this test because required command %s is missing", cmd)
		}
	}
}
