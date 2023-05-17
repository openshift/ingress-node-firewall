package events

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"

	ingressnodefwiov1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
	"github.com/openshift/ingress-node-firewall/test/e2e/daemonset"

	corev1 "k8s.io/api/core/v1"
)

type TestEvent struct {
	InterfaceName      string
	SourceAddress      string
	DestinationAddress string
	Action             ingressnodefwiov1alpha1.IngressNodeFirewallActionType
	Protocol           ingressnodefwiov1alpha1.IngressNodeFirewallRuleProtocolType
	// transport protocols only
	DestinationPort string
	// ICMP protocols
	IcmpType int
	IcmpCode int
}

func getFromDaemonLogsOnNode(client *testclient.ClientSet, namespace, nodeName string, timeout time.Duration) ([]TestEvent, error) {
	daemonsetPod, err := daemonset.GetDaemonSetOnNode(client, namespace, nodeName)
	if err != nil {
		return nil, err
	}

	request := client.CoreV1Interface.Pods(namespace).GetLogs(daemonsetPod.Name, &corev1.PodLogOptions{
		Container: "events",
	})
	if request == nil {
		return nil, fmt.Errorf("failed to get events container logs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	daemonsetLogsStream, err := request.Stream(ctx)
	if err != nil {
		return nil, err
	}
	defer daemonsetLogsStream.Close()

	buffer := new(bytes.Buffer)
	_, err = io.Copy(buffer, daemonsetLogsStream)
	if err != nil {
		return nil, fmt.Errorf("error in copying info from pod logs to buffer")
	}
	return extractEventsFromString(buffer.String())
}

func extractEventsFromString(str string) ([]TestEvent, error) {
	testEvents := make([]TestEvent, 0)
	// Transport regular expression
	// Match for each drop.
	// If any change to the event output in pkg/ebpf/ingress_node_firewall_events.go, an update is required here.
	transportEventRE := "ruleId\\s([0-9]+)\\saction\\s(?P<action>\\w+).*if\\s(?P<inf>\\w+)\n.*\\ssrc\\saddr\\s(?P<srcaddr>[0-9.:a-z]+)\\sdst\\saddr\\s(?P<dstaddr>[0-9.:a-z]+)\n.*(?P<proto>tcp|udp|sctp)\\ssrcPort\\s\\d+\\sdstPort\\s(?P<dstport>\\d+)"
	transportEventPattern := regexp.MustCompile(transportEventRE)
	for _, match := range transportEventPattern.FindAllStringSubmatch(str, -1) { // -1 for unlimited matches
		var te TestEvent
		te.InterfaceName = match[transportEventPattern.SubexpIndex("inf")]
		te.SourceAddress = match[transportEventPattern.SubexpIndex("srcaddr")]
		te.DestinationAddress = match[transportEventPattern.SubexpIndex("dstaddr")]
		actionStr := match[transportEventPattern.SubexpIndex("action")]
		if actionStr == "Drop" {
			te.Action = ingressnodefwiov1alpha1.IngressNodeFirewallDeny
		} else if actionStr == "Allow" {
			te.Action = ingressnodefwiov1alpha1.IngressNodeFirewallAllow
		} else {
			return nil, fmt.Errorf("unknown 'Action' %q", actionStr)
		}
		protocolStr := match[transportEventPattern.SubexpIndex("proto")]
		switch protocolStr {
		case "tcp":
			te.Protocol = ingressnodefwiov1alpha1.ProtocolTypeTCP
		case "udp":
			te.Protocol = ingressnodefwiov1alpha1.ProtocolTypeUDP
		case "sctp":
			te.Protocol = ingressnodefwiov1alpha1.ProtocolTypeSCTP
		default:
			return nil, fmt.Errorf("unknown or unexpected protocol %q", protocolStr)
		}
		te.DestinationPort = match[transportEventPattern.SubexpIndex("dstport")]
		testEvents = append(testEvents, te)
	}
	// ICMP regular expression
	// Match for each drop.
	// If any change to the event output in pkg/ebpf/ingress_node_firewall_events.go, an update is required here.
	icmpEventRE := "ruleId\\s([0-9]+)\\saction\\s(?P<action>\\w+).*if\\s(?P<inf>\\w+)\\n.*\\s(ipv4|ipv6)\\ssrc\\saddr\\s(?P<srcaddr>[0-9.:a-z]+)\\sdst\\saddr\\s(?P<dstaddr>[0-9.:a-z]+)\\n.*(?P<proto>icmpv4|icmpv6)\\stype\\s(?P<type>\\d+)\\scode\\s(?P<code>\\d+)"
	icmpEventPattern := regexp.MustCompile(icmpEventRE)
	for _, match := range icmpEventPattern.FindAllStringSubmatch(str, -1) {
		var te TestEvent
		te.InterfaceName = match[icmpEventPattern.SubexpIndex("inf")]
		te.SourceAddress = match[icmpEventPattern.SubexpIndex("srcaddr")]
		te.DestinationAddress = match[icmpEventPattern.SubexpIndex("dstaddr")]
		actionStr := match[icmpEventPattern.SubexpIndex("action")]
		if actionStr == "Drop" {
			te.Action = ingressnodefwiov1alpha1.IngressNodeFirewallDeny
		} else if actionStr == "Allow" {
			te.Action = ingressnodefwiov1alpha1.IngressNodeFirewallAllow
		} else {
			return nil, fmt.Errorf("unknown 'Action' %q", actionStr)
		}
		protocolStr := match[icmpEventPattern.SubexpIndex("proto")]
		// need to match on strings because ICMPv6 isn't fully upper case for type IngressNodeFirewallRuleProtocolType,
		// but all other protocols are, and we need to account for it
		switch protocolStr {
		case "icmpv4":
			te.Protocol = ingressnodefwiov1alpha1.ProtocolTypeICMP
		case "icmpv6":
			te.Protocol = ingressnodefwiov1alpha1.ProtocolTypeICMP6
		default:
			return nil, fmt.Errorf("unknown or unexpected protocol %q", protocolStr)
		}
		codeStr := match[icmpEventPattern.SubexpIndex("code")]
		codeInt, err := strconv.Atoi(codeStr)
		if err != nil {
			return nil, fmt.Errorf("unable to parse ICMP code %q: %v", codeStr, err)
		}
		te.IcmpCode = codeInt
		typeStr := match[icmpEventPattern.SubexpIndex("type")]
		typeInt, err := strconv.Atoi(typeStr)
		if err != nil {
			return nil, fmt.Errorf("unable tp parse ICMP type %q: %v", typeStr, err)
		}
		te.IcmpType = typeInt
		testEvents = append(testEvents, te)
	}
	return testEvents, nil
}

func DidEventOccur(client *testclient.ClientSet, namespace, node string, event TestEvent, timeout time.Duration) (bool, error) {
	occurredEvents, err := getFromDaemonLogsOnNode(client, namespace, node, timeout)
	if err != nil {
		return false, err
	}
	if isEventInList(occurredEvents, event) {
		return true, nil
	}
	return false, nil
}

func isEventInList(existingEvents []TestEvent, event TestEvent) bool {
	for _, existingEvent := range existingEvents {
		if existingEvent.InterfaceName != event.InterfaceName {
			continue
		}
		if existingEvent.SourceAddress != event.SourceAddress {
			continue
		}
		if existingEvent.DestinationAddress != event.DestinationAddress {
			continue
		}
		if existingEvent.Action != event.Action {
			continue
		}
		if existingEvent.Protocol != event.Protocol {
			continue
		}
		if existingEvent.DestinationPort != event.DestinationPort {
			continue
		}
		if existingEvent.IcmpType != event.IcmpType {
			continue
		}
		if existingEvent.IcmpCode != event.IcmpCode {
			continue
		}
		return true
	}
	return false
}

func GetICMPTestEvent(protocol ingressnodefwiov1alpha1.IngressNodeFirewallRuleProtocolType, inf, sourcePodIP,
	destinationPodIP string, icmpCode, icmpType int) TestEvent {
	return TestEvent{
		InterfaceName:      inf,
		SourceAddress:      sourcePodIP,
		DestinationAddress: destinationPodIP,
		Action:             ingressnodefwiov1alpha1.IngressNodeFirewallDeny,
		Protocol:           protocol,
		IcmpCode:           icmpCode,
		IcmpType:           icmpType,
	}
}

func GetTransportTestEvent(protocol ingressnodefwiov1alpha1.IngressNodeFirewallRuleProtocolType, inf, sourcePodIP,
	destinationPodIP, destinationPort string) TestEvent {
	return TestEvent{
		InterfaceName:      inf,
		SourceAddress:      sourcePodIP,
		DestinationAddress: destinationPodIP,
		Action:             ingressnodefwiov1alpha1.IngressNodeFirewallDeny,
		Protocol:           protocol,
		DestinationPort:    destinationPort,
	}
}
