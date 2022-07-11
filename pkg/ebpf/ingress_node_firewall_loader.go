package nodefwloader

import (
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"k8s.io/klog"

	ingressnodefwiov1alpha1 "ingress-node-firewall/api/v1alpha1"
)

const (
	XDPDeny  = 1 // XDP_DROP value
	XDPAllow = 2 // XDP_PASS value
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type ruleType_st bpf ../../bpf/ingress_node_firewall_kernel.c -- -I ../../bpf/headers -I/usr/include/x86_64-linux-gnu/
func IngressNodeFwRulesLoader(ingFireWallConfig ingressnodefwiov1alpha1.IngressNodeFirewallRules, isDelete bool) error {
	var err error

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		klog.Fatal(err)
		return err
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
		return err
	}
	defer objs.Close()

	info, err := objs.bpfMaps.IngressNodeFirewallTableMap.Info()
	if err != nil {
		klog.Fatalf("Cannot get map info: %v", err)
	}
	klog.Infof("Ingress node firewall map Info: %+v with FD %s", info, objs.bpfMaps.IngressNodeFirewallTableMap.String())

	if err := makeIngressFwRulesMap(objs, ingFireWallConfig, isDelete); err != nil {
		klog.Fatalf("Failed to create map info: %v", err)
		return err
	}
	return nil
}

func makeIngressFwRulesMap(objs bpfObjects, ingFirewallConfig ingressnodefwiov1alpha1.IngressNodeFirewallRules, isDelete bool) error {
	keys := []bpfBpfLpmIpKeySt{}
	rules := bpfRulesValSt{}
	var key bpfBpfLpmIpKeySt

	// Parse CIDRs to construct map key
	for _, cidr := range ingFirewallConfig.FromCIDRs {
		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			klog.Fatalf("Failed to parse FromCIDR: %v", err)
			return err
		}
		copy(key.U.Ip4Data[:], ip)
		pfLen, _ := ipNet.Mask.Size()
		key.PrefixLen = uint32(pfLen)
		keys = append(keys, key)
	}

	// Parse firewall rules
	rules.NumRules = uint32(len(ingFirewallConfig.FirewallProtocolRules))
	for idx, rule := range ingFirewallConfig.FirewallProtocolRules {
		rules.Rules[idx].RuleId = rule.Order
		switch rule.Protocol {
		case ingressnodefwiov1alpha1.ProtocolTypeTCP:
			copy(rules.Rules[idx].DstPorts[:], rule.ProtocolRule.Ports)
			rules.Rules[idx].Protocol = syscall.IPPROTO_TCP
		case ingressnodefwiov1alpha1.ProtocolTypeUDP:
			copy(rules.Rules[idx].DstPorts[:], rule.ProtocolRule.Ports)
			rules.Rules[idx].Protocol = syscall.IPPROTO_UDP
		case ingressnodefwiov1alpha1.ProtocolTypeSCTP:
			copy(rules.Rules[idx].DstPorts[:], rule.ProtocolRule.Ports)
			rules.Rules[idx].Protocol = syscall.IPPROTO_SCTP
		case ingressnodefwiov1alpha1.ProtocolTypeICMP:
			rules.Rules[idx].IcmpType = rule.ICMPRule.ICMPType
			rules.Rules[idx].IcmpCode = rule.ICMPRule.ICMPCode
			rules.Rules[idx].Protocol = syscall.IPPROTO_ICMP
		case ingressnodefwiov1alpha1.ProtocolTypeICMPv6:
			rules.Rules[idx].IcmpType = rule.ICMPRule.ICMPType
			rules.Rules[idx].IcmpCode = rule.ICMPRule.ICMPCode
			rules.Rules[idx].Protocol = syscall.IPPROTO_ICMPV6

		default:
			return fmt.Errorf("Failed invalid protocol %v", rule.Protocol)
		}
		switch rule.Action {
		case ingressnodefwiov1alpha1.IngressNodeFirewallAllow:
			rules.Rules[idx].Action = XDPAllow
		case ingressnodefwiov1alpha1.IngressNodeFirewallDeny:
			rules.Rules[idx].Action = XDPDeny
		default:
			return fmt.Errorf("Failed invalid action %v", rule.Action)
		}
	}

	// Handle Ingress firewall map operation
	if isDelete {
		if _, err := objs.bpfMaps.IngressNodeFirewallTableMap.BatchDelete(keys, &ebpf.BatchOptions{}); err != nil {
			klog.Fatalf("Failed Adding/Updating ingress firewall rules: %v", err)
			return err
		}
	} else {
		if _, err := objs.bpfMaps.IngressNodeFirewallTableMap.BatchUpdate(keys, rules, &ebpf.BatchOptions{}); err != nil {
			klog.Fatalf("Failed Deleting ingress firewall rules: %v", err)
			return err
		}
	}

	return nil
}

func IngessNodeFwAttach(ifacesName []string) error {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	for _, ifaceName := range ifacesName {
		// Look up the network interface by name.
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			log.Fatalf("lookup network iface %q: %s", ifaceName, err)
			return err
		}
		// Attach the program.
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.IngresNodeFirewallProcess,
			Interface: iface.Index,
		})
		if err != nil {
			log.Fatalf("could not attach XDP program: %s", err)
			return err
		}
		defer l.Close()
		log.Printf("Attached IngressNode Firewall program to iface %q (index %d)", iface.Name, iface.Index)
	}
	return nil
}
