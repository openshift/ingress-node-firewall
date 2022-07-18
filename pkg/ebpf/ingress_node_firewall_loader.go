package nodefwloader

import (
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"k8s.io/klog"

	ingressnodefwiov1alpha1 "ingress-node-firewall/api/v1alpha1"
)

const (
	xdpDeny   = 1 // XDP_DROP value
	xdpAllow  = 2 // XDP_PASS value
	bpfFSPath = "/sys/fs/bpf"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type ruleType_st -type event_hdr_st -type ruleStatistics_st bpf ../../bpf/ingress_node_firewall_kernel.c -- -I ../../bpf/headers -I/usr/include/x86_64-linux-gnu/
func IngressNodeFwRulesLoader(ingFireWallConfig ingressnodefwiov1alpha1.IngressNodeFirewallRules, ifacesName []string, isDelete bool) error {
	var err error

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		klog.Fatal(err)
		return err
	}

	pinDir := path.Join(bpfFSPath, "xdp_ingress_node_firewall_process")
	if err := os.MkdirAll(pinDir, os.ModePerm); err != nil {
		log.Fatalf("failed to create pinDir %s: %s", pinDir, err)
		return err
	}
	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}); err != nil {
		log.Fatalf("loading objects: pinDir:%s, err:%s", pinDir, err)
		return err
	}

	info, err := objs.bpfMaps.IngressNodeFirewallTableMap.Info()
	if err != nil {
		klog.Fatalf("Cannot get map info: %v", err)
	}
	klog.Infof("Ingress node firewall map Info: %+v with FD %s", info, objs.bpfMaps.IngressNodeFirewallTableMap.String())

	if err := makeIngressFwRulesMap(objs, ingFireWallConfig, isDelete); err != nil {
		klog.Fatalf("Failed to create map firewall rules: %v", err)
		return err
	}

	if err := ingessNodeFwAttach(objs, ifacesName, pinDir, isDelete); err != nil {
		klog.Fatalf("Failed to attach map firewall prog: %v", err)
		return err
	}

	if err := ingressNodeFwEvents(objs); err != nil {
		klog.Fatalf("Failed to load perf stats: %v", err)
		return err
	}
	return nil
}

func makeIngressFwRulesMap(objs bpfObjects, ingFirewallConfig ingressnodefwiov1alpha1.IngressNodeFirewallRules, isDelete bool) error {
	rules := bpfRulesValSt{}
	var key bpfBpfLpmIpKeySt

	// Parse firewall rules
	rules.NumRules = uint32(len(ingFirewallConfig.FirewallProtocolRules))
	for idx, rule := range ingFirewallConfig.FirewallProtocolRules {
		rules.Rules[idx].RuleId = rule.Order
		switch rule.Protocol {
		case ingressnodefwiov1alpha1.ProtocolTypeTCP:
			rules.Rules[idx].DstPort = rule.ProtocolRule.Port
			rules.Rules[idx].Protocol = syscall.IPPROTO_TCP
		case ingressnodefwiov1alpha1.ProtocolTypeUDP:
			rules.Rules[idx].DstPort = rule.ProtocolRule.Port
			rules.Rules[idx].Protocol = syscall.IPPROTO_UDP
		case ingressnodefwiov1alpha1.ProtocolTypeSCTP:
			rules.Rules[idx].DstPort = rule.ProtocolRule.Port
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
			rules.Rules[idx].Action = xdpAllow
		case ingressnodefwiov1alpha1.IngressNodeFirewallDeny:
			rules.Rules[idx].Action = xdpDeny
		default:
			return fmt.Errorf("Failed invalid action %v", rule.Action)
		}
	}

	// Parse CIDRs to construct map keys wih shared rules
	for _, cidr := range ingFirewallConfig.FromCIDRs {
		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			klog.Fatalf("Failed to parse FromCIDR: %v", err)
			return err
		}
		if ip.To4() != nil {
			copy(key.IpData[:], ip.To4())
		} else {
			copy(key.IpData[:], ip.To16())
		}
		pfLen, _ := ipNet.Mask.Size()
		key.PrefixLen = uint32(pfLen)
		// Handle Ingress firewall map operation
		if isDelete {
			log.Printf("Deleting ingress firewall rules for key %v", key)
			if err := objs.bpfMaps.IngressNodeFirewallTableMap.Delete(key); err != nil {
				klog.Fatalf("Failed Deleting ingress firewall rules: %v", err)
				return err
			}
		} else {
			log.Printf("Creating ingress firewall rules for key %v", key)
			if err := objs.bpfMaps.IngressNodeFirewallTableMap.Update(key, rules, ebpf.UpdateAny); err != nil {
				klog.Fatalf("Failed Adding/Updating ingress firewall rules: %v", err)
				return err
			}
		}
	}
	return nil
}

func ingessNodeFwAttach(objs bpfObjects, ifacesName []string, pinDir string, isDelete bool) error {
	for _, ifaceName := range ifacesName {
		// Look up the network interface by name.
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			log.Fatalf("lookup network iface %q: %s", ifaceName, err)
			return err
		}
		if !isDelete {
			// Attach the program.
			l, err := link.AttachXDP(link.XDPOptions{
				Program:   objs.IngresNodeFirewallProcess,
				Interface: iface.Index,
			})
			if err != nil {
				log.Fatalf("could not attach XDP program: %s", err)
				return err
			}

			lpinDir := path.Join(pinDir, ifaceName+"-link")
			if err := l.Pin(lpinDir); err != nil {
				log.Fatalf("failed to pin link to pinDir %s: %s", lpinDir, err)
				return err
			}
			log.Printf("Attached IngressNode Firewall program to iface %q (index %d)", iface.Name, iface.Index)
		} else {
			log.Printf("Unattaching IngressNode Firewall program from iface %q (index %d)", iface.Name, iface.Index)
			l, _ := link.AttachXDP(link.XDPOptions{
				Program:   objs.IngresNodeFirewallProcess,
				Interface: iface.Index,
			})
			l.Unpin()
			l.Close()
			objs.Close()
		}
	}
	return nil
}
