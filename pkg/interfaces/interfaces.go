package interfaces

import (
	"net"

	"github.com/vishvananda/netlink"
)

var (
	netInterfaces = net.Interfaces
)

func isUp(nif net.Interface) bool {
	return nif.Flags&net.FlagUp != 0
}

func isLoopback(nif net.Interface) bool {
	return nif.Flags&net.FlagLoopback != 0
}

// IsValidInterfaceNameAndState check if interface name is valid, interface state is UP and its not loopback interface
func IsValidInterfaceNameAndState(ifName string) bool {
	ifs, err := netInterfaces()
	if err != nil {
		return false
	}
	for _, inf := range ifs {
		if inf.Name == ifName && isUp(inf) && !isLoopback(inf) {
			return true
		}
	}
	return false
}

// GetInterfacesWithXDPAttached with XDP attached
func GetInterfacesWithXDPAttached() ([]string, error) {
	ifsList := make([]string, 0)
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, l := range links {
		if l.Attrs().Xdp != nil && l.Attrs().Xdp.Attached {
			ifsList = append(ifsList, l.Attrs().Name)
		}
	}
	return ifsList, nil
}
