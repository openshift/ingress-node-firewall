package nodefwloader

import (
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"syscall"

	ingressnodefwiov1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	"github.com/openshift/ingress-node-firewall/pkg/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"k8s.io/klog"
)

const (
	xdpDeny     = 1 // XDP_DROP value
	xdpAllow    = 2 // XDP_PASS value
	bpfFSPath   = "/sys/fs/bpf"
	xdpEBUSYErr = "device or resource busy"
)

// IngNodeFwController structure is the object hold controls for starting
// ingress node firewall resource
type IngNodeFwController struct {
	// eBPF objs to create/update eBPF maps
	objs BpfObjects
	// eBPF interfaces attachment objects
	links map[string]link.Link
	// eBPF pingPath
	pinPath string
}

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type ruleType_st -type event_hdr_st -type ruleStatistics_st Bpf ../../bpf/ingress_node_firewall_kernel.c -- -I ../../bpf/headers -I/usr/include/x86_64-linux-gnu/

// NewIngNodeFwController creates new IngressNodeFirewall controller object
func NewIngNodeFwController() (*IngNodeFwController, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	pinDir := path.Join(bpfFSPath, "xdp_ingress_node_firewall_process")
	if err := os.MkdirAll(pinDir, os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create pinDir %s: %s", pinDir, err)
	}
	// Load pre-compiled programs into the kernel.
	objs := BpfObjects{}
	if err := LoadBpfObjects(&objs, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}); err != nil {
		return nil, fmt.Errorf("loading objects: pinDir:%s, err:%s", pinDir, err)
	}
	return &IngNodeFwController{
		objs:    objs,
		pinPath: pinDir,
		links:   make(map[string]link.Link, 0),
	}, nil
}

// IngressNodeFwRulesLoader Add/Update/Delete ingress nod firewll rules to eBPF LPM MAP
func (infc *IngNodeFwController) IngressNodeFwRulesLoader(ingFireWallConfig ingressnodefwiov1alpha1.IngressNodeFirewallRules,
	isDelete bool, ifId uint32) error {
	objs := infc.objs
	info, err := objs.BpfMaps.IngressNodeFirewallTableMap.Info()
	if err != nil {
		return fmt.Errorf("Cannot get map info: %v on if %d", err, ifId)
	}
	klog.Infof("Ingress node firewall map Info: %+v with FD %s", info, objs.BpfMaps.IngressNodeFirewallTableMap.String())

	if err := infc.makeIngressFwRulesMap(ingFireWallConfig, isDelete, ifId); err != nil {
		return fmt.Errorf("Failed to create map firewall rules: %v on if %d", err, ifId)
	}

	infc.ingressNodeFwEvents()

	return nil
}

func (infc *IngNodeFwController) GetStatisticsMap() *ebpf.Map {
	return infc.objs.IngressNodeFirewallStatisticsMap
}

// makeIngressFwRulesMap convert IngressNodeFirewallRules into eBPF format which matched what the
// kerenl hook will be using.
func (infc *IngNodeFwController) makeIngressFwRulesMap(ingFirewallConfig ingressnodefwiov1alpha1.IngressNodeFirewallRules,
	isDelete bool, ifId uint32) error {
	objs := infc.objs
	rules := BpfRulesValSt{}
	var key BpfLpmIpKeySt

	// Parse firewall rules
	for _, rule := range ingFirewallConfig.FirewallProtocolRules {
		rule := rule
		idx := rule.Order
		rules.Rules[idx].RuleId = rule.Order
		switch rule.ProtocolConfig.Protocol {
		case ingressnodefwiov1alpha1.ProtocolTypeTCP:
			if utils.IsRange(rule.ProtocolConfig.TCP) {
				start, end, err := utils.GetRange(rule.ProtocolConfig.TCP)
				if err != nil {
					return fmt.Errorf("invalid Port range %s for protocol %v",
						rule.ProtocolConfig.TCP.Ports.String(), rule.ProtocolConfig.Protocol)
				}
				rules.Rules[idx].DstPortStart = start
				rules.Rules[idx].DstPortEnd = end
			} else {
				port, err := utils.GetPort(rule.ProtocolConfig.TCP)
				if err != nil {
					return fmt.Errorf("invalid Port %s for protocol %v",
						rule.ProtocolConfig.TCP.Ports.String(), rule.ProtocolConfig.Protocol)
				}
				rules.Rules[idx].DstPortStart = port
				rules.Rules[idx].DstPortEnd = 0
			}
			rules.Rules[idx].Protocol = syscall.IPPROTO_TCP
		case ingressnodefwiov1alpha1.ProtocolTypeUDP:
			if utils.IsRange(rule.ProtocolConfig.UDP) {
				start, end, err := utils.GetRange(rule.ProtocolConfig.UDP)
				if err != nil {
					return fmt.Errorf("invalid Port range %s for protocol %v",
						rule.ProtocolConfig.UDP.Ports.String(), rule.ProtocolConfig.Protocol)
				}
				rules.Rules[idx].DstPortStart = start
				rules.Rules[idx].DstPortEnd = end
			} else {
				port, err := utils.GetPort(rule.ProtocolConfig.UDP)
				if err != nil {
					return fmt.Errorf("invalid Port %s for protocol %v",
						rule.ProtocolConfig.UDP.Ports.String(), rule.ProtocolConfig.Protocol)
				}
				rules.Rules[idx].DstPortStart = port
				rules.Rules[idx].DstPortEnd = 0
			}
			rules.Rules[idx].Protocol = syscall.IPPROTO_UDP
		case ingressnodefwiov1alpha1.ProtocolTypeSCTP:
			if utils.IsRange(rule.ProtocolConfig.SCTP) {
				start, end, err := utils.GetRange(rule.ProtocolConfig.SCTP)
				if err != nil {
					return fmt.Errorf("invalid Port range %s for protocol %v",
						rule.ProtocolConfig.SCTP.Ports.String(), rule.ProtocolConfig.Protocol)
				}
				rules.Rules[idx].DstPortStart = start
				rules.Rules[idx].DstPortEnd = end
			} else {
				port, err := utils.GetPort(rule.ProtocolConfig.SCTP)
				if err != nil {
					return fmt.Errorf("invalid Port %s for protocol %v",
						rule.ProtocolConfig.SCTP.Ports.String(), rule.ProtocolConfig.Protocol)
				}
				rules.Rules[idx].DstPortStart = port
				rules.Rules[idx].DstPortEnd = 0
			}
			rules.Rules[idx].Protocol = syscall.IPPROTO_SCTP
		case ingressnodefwiov1alpha1.ProtocolTypeICMP:
			rules.Rules[idx].IcmpType = rule.ProtocolConfig.ICMP.ICMPType
			rules.Rules[idx].IcmpCode = rule.ProtocolConfig.ICMP.ICMPCode
			rules.Rules[idx].Protocol = syscall.IPPROTO_ICMP
		case ingressnodefwiov1alpha1.ProtocolTypeICMP6:
			rules.Rules[idx].IcmpType = rule.ProtocolConfig.ICMPv6.ICMPType
			rules.Rules[idx].IcmpCode = rule.ProtocolConfig.ICMPv6.ICMPCode
			rules.Rules[idx].Protocol = syscall.IPPROTO_ICMPV6

		default:
			return fmt.Errorf("Failed invalid protocol %v", rule.ProtocolConfig.Protocol)
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
	for _, cidr := range ingFirewallConfig.SourceCIDRs {
		cidr := cidr
		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("Failed to parse SourceCIDRs: %v", err)
		}
		if ip.To4() != nil {
			copy(key.IpData[:], ip.To4())
		} else {
			copy(key.IpData[:], ip.To16())
		}
		pfLen, _ := ipNet.Mask.Size()
		key.PrefixLen = uint32(pfLen)
		key.IngressIfindex = ifId
		// Handle Ingress firewall map operation
		if isDelete {
			log.Printf("Deleting ingress firewall rules for key %v", key)
			if err := objs.BpfMaps.IngressNodeFirewallTableMap.Delete(key); err != nil {
				return fmt.Errorf("Failed Deleting ingress firewall rules: %v", err)
			}
		} else {
			log.Printf("Creating ingress firewall rules for key %v", key)
			if err := objs.BpfMaps.IngressNodeFirewallTableMap.Update(key, rules, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("Failed Adding/Updating ingress firewall rules: %v", err)
			}
		}
	}
	return nil
}

// IngressNodeFwAttach attach eBPF program to list interfaces and pin them to different pinDir
func (infc *IngNodeFwController) IngressNodeFwAttach(ifacesName []string, isDelete bool) (map[string]uint32, error) {
	var ifMap = make(map[string]uint32, 0)

	objs := infc.objs
	for _, ifaceName := range ifacesName {
		ifaceName := ifaceName
		// Look up the network interface by name.
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return ifMap, fmt.Errorf("lookup network iface %q: %s", ifaceName, err)
		}
		ifMap[ifaceName] = uint32(iface.Index)
		if !isDelete {
			// Attach the program.
			l, err := link.AttachXDP(link.XDPOptions{
				Program:   objs.IngressNodeFirewallProcess,
				Interface: iface.Index,
			})
			if err != nil {
				if strings.Contains(err.Error(), xdpEBUSYErr) {
					log.Printf("Interface %s is already attached", ifaceName)
					return ifMap, nil
				}
				return ifMap, fmt.Errorf("could not attach XDP program: %s", err)
			}
			lPinDir := path.Join(infc.pinPath, ifaceName+"_link")
			if err := l.Pin(lPinDir); err != nil {
				return ifMap, fmt.Errorf("failed to pin link to pinDir %s: %s", lPinDir, err)
			}
			infc.links[ifaceName] = l
			log.Printf("Attached IngressNode Firewall program to iface %q (index %d)", iface.Name, iface.Index)
		} else {
			log.Printf("Unattaching IngressNode Firewall program from iface %q (index %d)", iface.Name, iface.Index)
			if err := infc.cleanup(ifaceName); err != nil {
				return ifMap, err
			}
		}
	}
	return ifMap, nil
}

// cleanup will delete interface's eBPF objects.
func (infc *IngNodeFwController) cleanup(ifName string) error {
	l, ok := infc.links[ifName]
	if !ok {
		return fmt.Errorf("failed to find Link object for interface %s", ifName)
	}
	if err := l.Unpin(); err != nil {
		return fmt.Errorf("failed to unpin link for %s err: %q", ifName, err)
	}
	if err := l.Close(); err != nil {
		return fmt.Errorf("failed to close and detach link %s err: %q", ifName, err)
	}
	delete(infc.links, ifName)
	return nil
}

func (infc *IngNodeFwController) CleaneBPFObjs() error {
	if err := infc.objs.Close(); err != nil {
		return fmt.Errorf("failed to close eBPF objs err: %q", err)
	}
	if err := os.RemoveAll(infc.pinPath); err != nil {
		return fmt.Errorf("failed to remove pinpath %s err: %q", infc.pinPath, err)
	}
	return nil
}
