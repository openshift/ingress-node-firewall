package utils

import (
	"fmt"
	"strconv"
	"strings"

	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"

	"k8s.io/apimachinery/pkg/util/intstr"
)

func IsRange(p *infv1alpha1.IngressNodeFirewallProtoRule) bool {
	if p.Ports.Type == intstr.String {
		return strings.Contains(p.Ports.String(), "-")
	}
	return false
}

func GetPort(p *infv1alpha1.IngressNodeFirewallProtoRule) (uint16, error) {
	if IsRange(p) {
		return 0, fmt.Errorf("port is a range and not an individual port")
	}
	port, err := strconv.ParseUint(p.Ports.String(), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid Port number %v", err)
	}
	if port == 0 {
		return 0, fmt.Errorf("invalid port number 0")
	}
	return uint16(port), nil
}

func GetRange(p *infv1alpha1.IngressNodeFirewallProtoRule) (uint16, uint16, error) {
	if !IsRange(p) {
		return 0, 0, fmt.Errorf("port is not a range")
	}
	ps := strings.SplitN(p.Ports.String(), "-", 2)
	if len(ps) != 2 {
		return 0, 0, fmt.Errorf("invalid ports range. Expected two integers seperated by hyphen but found  %q", p.Ports)
	}
	startPort, err := strconv.ParseUint(ps[0], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port number %s", err)
	}
	endPort, err := strconv.ParseUint(ps[1], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port number %s", err)
	}
	if startPort > endPort {
		return 0, 0, fmt.Errorf("invalid port range. Start port is greater than end port")
	}
	if startPort == endPort {
		return 0, 0, fmt.Errorf("invalid port range. Start and end port are equal. Remove the hyphen and enter a single port")
	}
	if startPort == 0 {
		return 0, 0, fmt.Errorf("invalid start port 0")
	}
	return uint16(startPort), uint16(endPort), nil
}
