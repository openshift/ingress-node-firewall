package interfaces

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	apierrors "k8s.io/apimachinery/pkg/util/errors"
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

// GetInterfaceIndex returns the interface index of the interface with the given name.
func GetInterfaceIndex(interfaceName string) (uint32, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return 0, fmt.Errorf("looking up network interface name %q: %s", interfaceName, err)
	}
	return uint32(iface.Index), nil
}

// DetachXDPFromAllInterfaces detaches XDP from all interfaces on the system.
func DetachXDPFromAllInterfaces() error {
	var errors []error

	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	for _, l := range links {
		if l.Attrs().Xdp != nil && l.Attrs().Xdp.Attached {
			if err := netlink.LinkSetXdpFd(l, -1); err != nil {
				errors = append(errors, err)
			}
		}
	}
	if len(errors) > 0 {
		return apierrors.NewAggregate(errors)
	}
	return nil
}
