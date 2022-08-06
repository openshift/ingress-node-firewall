package ebpfsyncer

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"sync"
	"testing"
	"time"

	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

const (
	interfacePrefix   = "dummy"
	netnsName         = "dummy"
	testProto         = "tcp"
	testPort          = 12345
	numTestInterfaces = 3
)

// var originalNetNS netns.NsHandle
// var newNetNS netns.NsHandle
// var newNetNSName string
var interfaces []netlink.Veth

// TestSyncInterfaceIngressRulesConnectDenyRule attaches rules to an interfaces and verifies that the rules work.
func TestSyncInterfaceIngressRulesConnectDenyRule(t *testing.T) {
	checkCommandDependenciesOrSkip(t, []string{"nc"})

	defer afterEach(t)
	beforeEach(t)

	rules := map[string][]infv1alpha1.IngressNodeFirewallRules{
		fmt.Sprintf("%s0", interfacePrefix): {
			{
				SourceCIDRs: []string{"192.0.2.0/24"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
							Protocol: infv1alpha1.ProtocolTypeTCP,
							TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
								Ports: intstr.FromInt(testPort),
							},
						},
						Action: infv1alpha1.IngressNodeFirewallDeny,
					},
				},
			},
		},
	}

	ctx := context.Background()
	fmt.Println("Running a server that's listening on", testProto, testPort)
	go func() {
		_ = runListenServer(ctx, testProto, testPort)
	}()

	fmt.Println("Giving the server a few seconds to start")
	time.Sleep(2 * time.Second)

	fmt.Println("Trying to connect to the server (should succeed)", testProto, testPort)
	err := testTCP("192.0.2.1", testPort)
	if err != nil {
		t.Fatal(err)
	}

	l := zap.New()
	fmt.Println("Running the ebpfsyncer's sync to attach rules")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Waiting a little")
	time.Sleep(2 * time.Second)

	fmt.Println("Trying to connect to the server (should fail)", testProto, testPort)
	err = testTCP("192.0.2.1", testPort)
	if err == nil {
		t.Fatal("Connection to server was succesful but it shouldn't be")
	}
}

// TestSyncInterfaceIngressRulesConnectAllowRule attaches rules to an interfaces and verifies that the rules work.
func TestSyncInterfaceIngressRulesConnectAllowRule(t *testing.T) {
	checkCommandDependenciesOrSkip(t, []string{"nc"})

	defer afterEach(t)
	beforeEach(t)

	rules := map[string][]infv1alpha1.IngressNodeFirewallRules{
		fmt.Sprintf("%s0", interfacePrefix): {
			{
				SourceCIDRs: []string{"192.0.2.0/24"},
				FirewallProtocolRules: []infv1alpha1.IngressNodeFirewallProtocolRule{
					{
						Order: 10,
						ProtocolConfig: infv1alpha1.IngressNodeProtocolConfig{
							Protocol: infv1alpha1.ProtocolTypeTCP,
							TCP: &infv1alpha1.IngressNodeFirewallProtoRule{
								Ports: intstr.FromInt(testPort),
							},
						},
						Action: infv1alpha1.IngressNodeFirewallAllow,
					},
				},
			},
		},
	}

	ctx := context.Background()
	fmt.Println("Running a server that's listening on", testProto, testPort)
	go func() {
		_ = runListenServer(ctx, testProto, testPort)
	}()

	fmt.Println("Giving the server a few seconds to start")
	time.Sleep(2 * time.Second)

	fmt.Println("Trying to connect to the server (should succeed)", testProto, testPort)
	err := testTCP("192.0.2.1", testPort)
	if err != nil {
		t.Fatal(err)
	}

	l := zap.New()
	fmt.Println("Running the ebpfsyncer's sync to attach rules")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Waiting a little")
	time.Sleep(2 * time.Second)

	fmt.Println("Trying to connect to the server (should succeed)", testProto, testPort)
	err = testTCP("192.0.2.1", testPort)
	if err != nil {
		t.Fatal(err)
	}
}

// TestSyncInterfaceIngressRulesAttachAndDetachSingleInterface attaches and detaches rules from interfaces 2x in a row to test
// that this operation works.
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
								Ports: intstr.FromInt(testPort),
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
								Ports: intstr.FromInt(testPort),
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
	fmt.Println("Running the ebpfsyncer's sync to attach rules")
	err := GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Running ebpfsyncer's sync to delete rules")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, true)
	if err != nil {
		t.Fatal(err)
	}

	// Work around https://github.com/openshift/ingress-node-firewall/issues/92
	time.Sleep(time.Second)

	fmt.Println("Running the ebpfsyncer's sync to attach rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Running ebpfsyncer's sync to delete rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, true)
	if err != nil {
		t.Fatal(err)
	}
}

// TestSyncInterfaceIngressRulesAttachAndDetach attaches and detaches rules from interfaces 2x in a row to test
// that this operation works.
func TestSyncInterfaceIngressRulesAttachAndDetach(t *testing.T) {
	t.Skip()

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
								Ports: intstr.FromInt(testPort),
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
								Ports: intstr.FromInt(testPort),
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
								Ports: intstr.FromInt(testPort),
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
	fmt.Println("Running the ebpfsyncer's sync to attach rules")
	err := GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Running ebpfsyncer's sync to delete rules")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, true)
	if err != nil {
		t.Fatal(err)
	}

	// Work around https://github.com/openshift/ingress-node-firewall/issues/92
	time.Sleep(time.Second)

	fmt.Println("Running the ebpfsyncer's sync to attach rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Running ebpfsyncer's sync to delete rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, true)
	if err != nil {
		t.Fatal(err)
	}
}

// TestSyncInterfaceIngressRulesAttachAndDetachSingleInterface calls the rule attach twice in a row to test idempotency.
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
								Ports: intstr.FromInt(testPort),
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
								Ports: intstr.FromInt(testPort),
							},
						},
						Action: infv1alpha1.IngressNodeFirewallDeny,
					},
				},
			},
		},
	}

	ctx := context.Background()
	fmt.Println("Running the ebpfsyncer's sync to attach rules")
	l := zap.New()
	err := GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Running the ebpfsyncer's sync to attach rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatal(err)
	}
}

// TestSyncInterfaceIngressRulesAttachAndDetach calls the rule attach twice in a row to test idempotency.
func TestResyncInterfaceIngressRules(t *testing.T) {
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
								Ports: intstr.FromInt(testPort),
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
								Ports: intstr.FromInt(testPort),
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
								Ports: intstr.FromInt(testPort),
							},
						},
						Action: infv1alpha1.IngressNodeFirewallAllow,
					},
				},
			},
		},
	}

	ctx := context.Background()
	fmt.Println("Running the ebpfsyncer's sync to attach rules")
	l := zap.New()
	err := GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatalf("Failed attach operation, err: %q", err)
	}

	fmt.Println("Running the ebpfsyncer's sync to attach rules again")
	err = GetEbpfSyncer(ctx, l, nil, nil).SyncInterfaceIngressRules(rules, false)
	if err != nil {
		t.Fatalf("Failed attach operation, err: %q", err)
	}
}

func runListenServer(ctx context.Context, protocol string, port int) error {
	ln, err := net.Listen(protocol, fmt.Sprintf(":%d", port))
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

func testTCP(ip string, port int) error {
	cmd := exec.Command("ip", "netns", "exec", netnsName, "nc", "-w", "2", "-z", ip, fmt.Sprintf("%d", port))
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func cleanup(t *testing.T) {
	fmt.Println("Deleting all XDP pins")
	err := os.RemoveAll("/sys/fs/bpf/xdp_ingress_node_firewall_process")
	if err != nil {
		t.Log(err)
	}

	fmt.Println("Deleting the test interfaces")
	for i := range interfaces {
		err = netlink.LinkDel(&interfaces[i])
		if err != nil {
			t.Log(err)
		}
	}

	fmt.Println("Deleting the netns")
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
	fmt.Println("Checking if this test runs with sufficiently high privileges")
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("Unable to get current user: %s", err)
	}
	if currentUser.Uid != "0" {
		t.Skipf("Skipping this test due to insufficient privileges")
	}

	// Generate test interfaces and populate the slice. Then, run the cleanup (that way, we can delete the interfaces
	// if they already exist).
	fmt.Println("By populating the interface list")
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
	fmt.Println("By running a cleanup")
	cleanup(t)

	fmt.Println("By creating the namespace")
	cmd := exec.Command("ip", "netns", "add", netnsName)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("ip", "netns", "exec", netnsName, "ip", "link", "set", "dev", "lo", "up")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}

	// Now, actually create the interfaces.
	fmt.Println("By creating new test interfaces for testing")
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

		fmt.Println("By moving the peer interfaces to their own namespace and by assigning an IP")
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
