package interfaces

import (
	"net"
	"os/user"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestIsValidInterfaceNameAndState(t *testing.T) {
	prevNetInterfaces := netInterfaces
	t.Cleanup(func() {
		netInterfaces = prevNetInterfaces
	})
	netInterfaces = func() ([]net.Interface, error) {
		return []net.Interface{
			{
				Name:  "lo",
				Flags: net.FlagLoopback,
			},
			{
				Name:  "eth0",
				Flags: net.FlagUp,
			},
			{
				Name: "eth1",
			},
		}, nil
	}

	tests := []struct {
		name     string
		inf      string
		expected bool
	}{
		{
			name:     "valid interface name and in the up state",
			inf:      "eth0",
			expected: true,
		},
		{
			name:     "valid interface name and in the down state",
			inf:      "eth1",
			expected: false,
		},
		{
			name:     "loopback interface",
			inf:      "lo",
			expected: false,
		},
		{
			name:     "valid interface name but doesn't exits",
			inf:      "ensp1",
			expected: false,
		},
	}
	for _, tt := range tests {
		got := IsValidInterfaceNameAndState(tt.inf)
		if got != tt.expected {
			t.Errorf("%s: wrong\n got: %v\nwant: %v\n", tt.name, got, tt.expected)
		}
	}
}

func TestGetInterfaceIndices(t *testing.T) {
	var slaves []*netlink.Dummy
	bondInterfaceName := "bond"
	testSlaveInterfaces := []string{"packet1", "packet2", "packet3", "packet4"}
	user, err := user.Current()
	if err != nil {
		t.Fatalf("Unable to get user: %s", err)
	}
	if user.Uid != "0" {
		t.Skipf("Skipping this test due to insufficient privileges")
	}

	t.Log("By creating bond interfaces with members")
	bond := netlink.NewLinkBond(netlink.LinkAttrs{Name: bondInterfaceName})
	if err := netlink.LinkAdd(bond); err != nil {
		t.Fatal(err)
	}
	t.Logf("bond interface index %d", bond.Attrs().Index)
	defer func() {
		if err := netlink.LinkDel(bond); err != nil {
			t.Errorf("failed to delete bond link: %s", err)
		}
	}()
	for _, inf := range testSlaveInterfaces {
		slaveDummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: inf}}
		if err := netlink.LinkAdd(slaveDummy); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetBondSlave(slaveDummy, bond); err != nil {
			t.Fatal(err)
		}
		slaves = append(slaves, slaveDummy)
	}

	defer func() {
		for _, slave := range slaves {
			if err := netlink.LinkDel(slave); err != nil {
				t.Errorf("failed to delete bond member link: %s", err)
			}
		}
	}()

	list, err := GetInterfaceIndices(bondInterfaceName)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != len(testSlaveInterfaces) {
		t.Errorf("expected to get %d members for the bond interface but got %d", len(testSlaveInterfaces), len(list))
	}

	for idx, i := range list {
		t.Logf("%s interface index %d", testSlaveInterfaces[idx], i)
	}

}
