package interfaces

import (
	"net"
	"testing"
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
