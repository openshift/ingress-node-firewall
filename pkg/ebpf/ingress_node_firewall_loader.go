package nodefwloader

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"unsafe"

	"github.com/openshift/ingress-node-firewall/api/v1alpha1"
	ingressnodefwiov1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	"github.com/openshift/ingress-node-firewall/pkg/interfaces"
	libxdploader "github.com/openshift/ingress-node-firewall/pkg/libxdploader"
	"github.com/openshift/ingress-node-firewall/pkg/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	apierrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog"
)

const (
	xdpDeny                       = 1 // XDP_DROP value
	xdpAllow                      = 2 // XDP_PASS value
	bpfFSPath                     = "/sys/fs/bpf"
	xdpIngressNodeFirewallProcess = "xdp_ingress_node_firewall_process"
	progSuffix                    = "_prog"
	ifIndexKeyLength              = 32 // Interface Index key length in bits
)

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		klog.Fatalf("Could not determine native endianness.")
	}
}

// IngNodeFwController structure is the object hold controls for starting
// ingress node firewall resource
type IngNodeFwController struct {
	// eBPF objs to create/update eBPF maps
	objs BpfObjects
	// eBPF interfaces attachment objects
	progs map[string]libxdploader.XdpProgram
	// eBPF pingPath
	pinPath string
}

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type ruleType_st -type event_hdr_st -type ruleStatistics_st Bpf ../../bpf/ingress_node_firewall_kernel.c -- -I ../../bpf/headers -I/usr/include/x86_64-linux-gnu/

// NewIngNodeFwController creates new IngressNodeFirewall controller object.
func NewIngNodeFwController() (*IngNodeFwController, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	pinDir := path.Join(bpfFSPath, xdpIngressNodeFirewallProcess)
	if err := os.MkdirAll(pinDir, os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create pinDir %s: %s", pinDir, err)
	}
	// Load pre-compiled programs into the kernel.
	objs := BpfObjects{}
	if err := LoadBpfObjects(&objs, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}); err != nil {
		return nil, fmt.Errorf("loading objects: pinDir:%s, err:%s", pinDir, err)
	}
	infc := &IngNodeFwController{
		objs:    objs,
		pinPath: pinDir,
		progs:   make(map[string]libxdploader.XdpProgram, 0),
	}
	// Load pinned programs from /sys/fs/bpf/xdp_ingress_node_firewall_process on initialization.
	// That way, the state in /sys/fs/bpf/xdp_ingress_node_firewall_process and the tracked list of programs
	// will be in sync.
	if err := infc.loadPinnedProgs(); err != nil {
		return nil, err
	}

	// Generate ingress node fw events
	if err := infc.ingressNodeFwEvents(); err != nil {
		return nil, err
	}

	return infc, nil
}

// IngressNodeFwRulesLoader adds/updates/deletes ingress node firewall rules to the eBPF LPM MAP in an idempotent way.
// IngressNodeFwRulesLoader executes the following actions in order:
// i)   Get eBPF objs to create/update eBPF maps and get map info.
// ii)  Build a map of valid ebpfKeys pointing to the ebpfRules that should be associated to them (built from
//
//	ifaceIngressRules).
//
// iii) Get stale keys (= keys inside the eBPF map but not inside the currently desired ruleset).
// iv)  Purge all stale keys from the eBPF map.
// v)   Add/update all keys. This is an idempotent action and non-existing keys are added whereas existing keys
//
//	are updated.
//
// vi)  Generate ingress node firewall events.
// In the context of this method, stale keys are keys that figure inside the eBPF map but that are not generated
// during step ii) from the provided ingressRules slice.
func (infc *IngNodeFwController) IngressNodeFwRulesLoader(
	ifaceIngressRules map[string][]v1alpha1.IngressNodeFirewallRules) error {
	// Get eBPF objs to create/update eBPF maps and get map info.
	info, err := infc.objs.BpfMaps.IngressNodeFirewallTableMap.Info()
	if err != nil {
		return fmt.Errorf("cannot get map info: %v", err)
	}
	klog.Infof("Ingress node firewall map Info: %+v with FD %s", info, infc.objs.BpfMaps.IngressNodeFirewallTableMap.String())

	// Convert IngressNodeFirewallRules into data that can be written to the BPF map.
	// Build a map of valid ebpfKeys pointing to the ebpfRules that should be associated to them.
	ebpfKeyToRules := make(map[BpfLpmIpKeySt]BpfRulesValSt)
	for interfaceName, ingressRules := range ifaceIngressRules {
		// Look up the network interface by name.
		ifID, err := interfaces.GetInterfaceIndex(interfaceName)
		if err != nil {
			return err
		}

		// Convert each provided ingressRule into a mapping of potentially multiple keys (one for each CIDR)
		// pointing to a flattened rule that can be written to the BPF map.
		for _, rule := range ingressRules {
			if ebpfKeys, ebpfRules, err := infc.makeIngressFwRulesMap(rule, ifID); err == nil {
				for _, ebpfKey := range ebpfKeys {
					ebpfKeyToRules[ebpfKey] = ebpfRules
				}
			} else {
				return fmt.Errorf("failed to create map firewall rules: %v on if %d", err, ifID)
			}
		}
	}

	// Build a slice of desired keys - it's easier to iterate over this slice later.
	var desiredKeys []BpfLpmIpKeySt
	for desiredKey := range ebpfKeyToRules {
		desiredKeys = append(desiredKeys, desiredKey)
	}

	// Get stale keys (= keys inside the eBPF map but not inside the currently desired ruleset). Those keys
	// will be dropped in the next step.
	staleKeys, err := infc.getStaleKeys(desiredKeys)
	if err != nil {
		return err
	}

	// Purge all stale keys from the eBPF map.
	if err := infc.purgeKeys(staleKeys); err != nil {
		klog.Infof("Purge keys operation encountered issues, err: %q", err)
	}

	// Add/update all keys. This is an idempotent action and non-existing keys are added whereas existing keys
	// are updated.
	if err := infc.addOrUpdateRules(ebpfKeyToRules); err != nil {
		return err
	}

	return nil
}

// addOrUpdateRules is a small method containing this limited set of functionality to facilitate unit testing of
// this part of code.
// FIXME: addOrUpdateRules seems to ignore interface indexes during the UpdateAny operation. Cf. the corresponding
// unit test.
func (infc *IngNodeFwController) addOrUpdateRules(ebpfKeyToRules map[BpfLpmIpKeySt]BpfRulesValSt) error {
	for ebpfKey, ebpfRules := range ebpfKeyToRules {
		log.Printf("Adding or updating ingress firewall rules for key %v", ebpfKey)
		if err := infc.objs.BpfMaps.IngressNodeFirewallTableMap.Update(ebpfKey, ebpfRules, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("Failed Adding/Updating ingress firewall rules: %v", err)
		}
	}
	return nil
}

// GetStatisticsMap returns the statistics map of the object.
func (infc *IngNodeFwController) GetStatisticsMap() *ebpf.Map {
	return infc.objs.IngressNodeFirewallStatisticsMap
}

// IngressNodeFwAttach attaches the eBPF program to a given list of interfaces and pins them to different pinDirs.
// For each provided interface name:
// i)   Look up the network interface by name.
// ii)  Attach the program to the interface.
// iii) Pin the XDP program.
func (infc *IngNodeFwController) IngressNodeFwAttach(ifacesName ...string) error {
	var errors []error
	for _, ifaceName := range ifacesName {
		if _, ok := infc.progs[ifaceName]; ok {
			klog.Infof("Interface %s is already attached and managed, skipping", ifaceName)
			continue
		}
		// Look up the network interface by name.
		ifID, err := interfaces.GetInterfaceIndex(ifaceName)
		if err != nil {
			errors = append(errors, err)
			continue
		}

		// Attach the program.
		xdpProgramName := "../ebpf/bpf_bpfel.o"
		if nativeEndian == binary.BigEndian {
			xdpProgramName = "../ebpf/bpf_bpfeb.o"
		}
		xdpProgram := libxdploader.LoadXdpProgram(xdpProgramName, infc.pinPath)
		if xdpProgram == nil {
			errors = append(errors, fmt.Errorf("failed to load XDP program %v", xdpProgram))
			continue
		}
		if rc := libxdploader.XdpAttachProgram(xdpProgram, int(ifID)); rc != 0 {
			errors = append(errors, fmt.Errorf("could not attach XDP program %v: %d", xdpProgram, rc))
			continue
		}
		log.Printf("Attached IngressNode Firewall program %v to iface %q (index %d)", xdpProgram, ifaceName, ifID)
		infc.progs[ifaceName] = xdpProgram
	}

	if len(errors) > 0 {
		return apierrors.NewAggregate(errors)
	}
	return nil
}

// IngressNodeFwDetach detaches the eBPF program from the list of interfaces and cleans up the interfaces.
// Additionally, it unloads all firewall rules that are associated to the interfaces.
func (infc *IngNodeFwController) IngressNodeFwDetach(interfaceNames ...string) error {
	var errors []error
	// Detach from interfaces.
	for _, interfaceName := range interfaceNames {
		log.Printf("Detaching IngressNode Firewall program from interface %q", interfaceName)
		if err := infc.cleanup(interfaceName); err != nil {
			errors = append(errors, err)
		} else {
			pinDir := path.Join(infc.pinPath, interfaceName+progSuffix)
			if err := os.RemoveAll(pinDir); err != nil {
				errors = append(errors, err)
			}
		}
	}
	if len(errors) > 0 {
		return apierrors.NewAggregate(errors)
	}

	return nil
}

// GetBPFMapContentForTest lists all existing keys and rules inside the map. Used for unit testing.
func (infc *IngNodeFwController) GetBPFMapContentForTest() (map[BpfLpmIpKeySt]BpfRulesValSt, error) {
	objs := infc.objs

	// Lookup all keys inside the map and find keys that are stale.
	keysToRules := make(map[BpfLpmIpKeySt]BpfRulesValSt)
	var key BpfLpmIpKeySt
	var value BpfRulesValSt
	iterator := objs.BpfMaps.IngressNodeFirewallTableMap.Iterate()
	for iterator.Next(&key, &value) {
		keysToRules[key] = value
	}
	err := iterator.Err()
	if err != nil {
		return nil, err
	}

	return keysToRules, nil
}

// Close closes the current objs and removes all interface pins and the ebpf table map.
func (infc *IngNodeFwController) Close() error {
	var errors []error

	klog.Info("Removing all pins")
	if err := infc.removeAllPins(); err != nil {
		errors = append(errors, fmt.Errorf("could not remove all eBPF pins, err: %q", err))
	}

	klog.Info("Removing table map")
	if err := infc.removeTableMap(); err != nil {
		errors = append(errors, fmt.Errorf("could not remove eBPF table map, err: %q", err))
	}

	klog.Info("Running cleanup of eBPF objects")
	if err := infc.cleaneBPFObjs(); err != nil {
		errors = append(errors, fmt.Errorf("could not clean eBPF objects, err: %q", err))
	}

	if len(errors) > 0 {
		return apierrors.NewAggregate(errors)
	}
	return nil
}

// cleaneBPFObjs closes the current objs.
func (infc *IngNodeFwController) cleaneBPFObjs() error {
	if err := infc.objs.Close(); err != nil {
		return fmt.Errorf("failed to close eBPF objs err: %q", err)
	}
	return nil
}

// removeAllPins removes all pins for XDP.
func (infc *IngNodeFwController) removeAllPins() error {
	files, err := ioutil.ReadDir(infc.pinPath)
	if err != nil {
		return err
	}

	re, err := regexp.Compile(".*" + progSuffix + "$")
	if err != nil {
		return err
	}
	for _, file := range files {
		if re.Match([]byte(file.Name())) {
			if err := os.Remove(path.Join(infc.pinPath, file.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// removeTableMap removes the ebpf table map.
func (infc *IngNodeFwController) removeTableMap() error {
	return os.Remove(path.Join(infc.pinPath, "ingress_node_firewall_table_map"))
}

// loadPinnedProgs loads any pinned programs that reside inside the /sys mount into memory if no such memory representation
// exists yet.
func (infc *IngNodeFwController) loadPinnedProgs() error {
	klog.Info("Loading interfaces from pinned dir into memory")
	files, err := ioutil.ReadDir(infc.pinPath)
	if err != nil {
		return err
	}

	re, err := regexp.Compile(".*" + progSuffix + "$")
	if err != nil {
		return err
	}

	for _, file := range files {
		if re.Match([]byte(file.Name())) {
			interfaceName := strings.TrimSuffix(file.Name(), progSuffix)
			if _, ok := infc.progs[interfaceName]; !ok {
				xdpPinPath := path.Join(infc.pinPath, file.Name())
				p := libxdploader.FindXdpProgramFromPin(xdpPinPath)
				if p == nil {
					return fmt.Errorf("failed to load XDP program from pinPath %s", xdpPinPath)
				}
				infc.progs[interfaceName] = p
			}
		}
	}

	return nil
}

// cleanup will delete an interface's eBPF objects.
func (infc *IngNodeFwController) cleanup(ifName string) error {
	p, ok := infc.progs[ifName]
	if !ok {
		return fmt.Errorf("failed to find XDP program object for interface %s", ifName)
	}
	ifID, err := interfaces.GetInterfaceIndex(ifName)
	if err != nil {
		return err
	}

	log.Printf("Running XDP program detach for  %v", p)
	if rc := libxdploader.XdpDetachProgram(p, int(ifID)); rc != 0 {
		return fmt.Errorf("failed to detach %v from  %s err: %d", p, ifName, rc)
	}

	libxdploader.CloseProgram(p)
	delete(infc.progs, ifName)
	return nil
}

// makeIngressFwRulesMap converts IngressNodeFirewallRules into eBPF format which matches what the
// kernel hook will be using. It returns the valid keys and the rules associated to those keys, or an error in case
// of issues. If multiple keys are returned then the rules must be attached to each of these keys.
func (infc *IngNodeFwController) makeIngressFwRulesMap(
	ingFirewallConfig ingressnodefwiov1alpha1.IngressNodeFirewallRules, ifID uint32) ([]BpfLpmIpKeySt, BpfRulesValSt, error) {
	rules := BpfRulesValSt{}
	var keys []BpfLpmIpKeySt

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
					return keys, rules, fmt.Errorf("invalid Port range %s for protocol %v",
						rule.ProtocolConfig.TCP.Ports.String(), rule.ProtocolConfig.Protocol)
				}
				rules.Rules[idx].DstPortStart = start
				rules.Rules[idx].DstPortEnd = end
			} else {
				port, err := utils.GetPort(rule.ProtocolConfig.TCP)
				if err != nil {
					return keys, rules, fmt.Errorf("invalid Port %s for protocol %v",
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
					return keys, rules, fmt.Errorf("invalid Port range %s for protocol %v",
						rule.ProtocolConfig.UDP.Ports.String(), rule.ProtocolConfig.Protocol)
				}
				rules.Rules[idx].DstPortStart = start
				rules.Rules[idx].DstPortEnd = end
			} else {
				port, err := utils.GetPort(rule.ProtocolConfig.UDP)
				if err != nil {
					return keys, rules, fmt.Errorf("invalid Port %s for protocol %v",
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
					return keys, rules, fmt.Errorf("invalid Port range %s for protocol %v",
						rule.ProtocolConfig.SCTP.Ports.String(), rule.ProtocolConfig.Protocol)
				}
				rules.Rules[idx].DstPortStart = start
				rules.Rules[idx].DstPortEnd = end
			} else {
				port, err := utils.GetPort(rule.ProtocolConfig.SCTP)
				if err != nil {
					return keys, rules, fmt.Errorf("invalid Port %s for protocol %v",
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
			return keys, rules, fmt.Errorf("Failed invalid protocol %v", rule.ProtocolConfig.Protocol)
		}
		switch rule.Action {
		case ingressnodefwiov1alpha1.IngressNodeFirewallAllow:
			rules.Rules[idx].Action = xdpAllow
		case ingressnodefwiov1alpha1.IngressNodeFirewallDeny:
			rules.Rules[idx].Action = xdpDeny
		default:
			return keys, rules, fmt.Errorf("Failed invalid action %v", rule.Action)
		}
	}

	// Parse CIDRs to construct map keys wih shared rules.
	for _, cidr := range ingFirewallConfig.SourceCIDRs {
		cidr := cidr
		key, err := BuildEBPFKey(ifID, cidr)
		if err != nil {
			return keys, rules, err
		}
		keys = append(keys, key)
	}
	return keys, rules, nil
}

// BuildEBPFKey builds a key object from an ifID and a cidr.
func BuildEBPFKey(ifID uint32, cidr string) (BpfLpmIpKeySt, error) {
	var key BpfLpmIpKeySt

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return key, fmt.Errorf("Failed to parse SourceCIDRs: %v", err)
	}
	if ip.To4() != nil {
		copy(key.IpData[:], ip.To4())
	} else {
		copy(key.IpData[:], ip.To16())
	}
	pfLen, _ := ipNet.Mask.Size()
	key.PrefixLen = uint32(pfLen) + ifIndexKeyLength
	key.IngressIfindex = ifID

	return key, nil
}

// getStaleKeys goes through all existing rules and lists keys from the ebpfMap that do not match any
// of the provided keys.
func (infc *IngNodeFwController) getStaleKeys(desiredKeys []BpfLpmIpKeySt) ([]BpfLpmIpKeySt, error) {
	objs := infc.objs

	// Lookup all keys inside the map and find keys that are stale.
	var staleKeys []BpfLpmIpKeySt
	var key BpfLpmIpKeySt
	var value BpfRulesValSt
	iterator := objs.BpfMaps.IngressNodeFirewallTableMap.Iterate()
	for iterator.Next(&key, &value) {
		keyFound := false
		for _, desiredKey := range desiredKeys {
			if reflect.DeepEqual(desiredKey, key) {
				keyFound = true
				break
			}
		}
		if !keyFound {
			staleKeys = append(staleKeys, BpfLpmIpKeySt{
				PrefixLen:      key.PrefixLen,
				IpData:         key.IpData,
				IngressIfindex: key.IngressIfindex,
			})
		}
	}
	err := iterator.Err()
	if err != nil {
		return staleKeys, err
	}

	return staleKeys, nil
}

// getStaleInterfaceKeys returns the keys for all rules that belong to stale interfaces, meaning interfaces
// that are not attached any more.
//
//nolint:golint,unused
func (infc *IngNodeFwController) getStaleInterfaceKeys() ([]BpfLpmIpKeySt, error) {
	objs := infc.objs

	// Looup all valid interfaces IDs.
	var validInterfaceIDs []uint32
	for interfaceName := range infc.progs {
		ifID, err := interfaces.GetInterfaceIndex(interfaceName)
		if err != nil {
			return nil, err
		}
		validInterfaceIDs = append(validInterfaceIDs, ifID)
	}

	// Lookup all keys inside the map and find keys that should be deleted.
	var keysToDelete []BpfLpmIpKeySt
	var key BpfLpmIpKeySt
	var value BpfRulesValSt
	iterator := objs.BpfMaps.IngressNodeFirewallTableMap.Iterate()
	for iterator.Next(&key, &value) {
		keyFound := false
		for _, validID := range validInterfaceIDs {
			if validID == key.IngressIfindex {
				keyFound = true
				break
			}
		}
		if !keyFound {
			keysToDelete = append(keysToDelete, BpfLpmIpKeySt{
				PrefixLen:      key.PrefixLen,
				IpData:         key.IpData,
				IngressIfindex: key.IngressIfindex,
			})
		}
	}
	err := iterator.Err()
	if err != nil {
		return nil, err
	}

	return keysToDelete, nil
}

// purgeKeys purges the provided keys from the eBPF map. If a key deletion fails, the error is added to a list
// of errors which will be returned at the end.
func (infc *IngNodeFwController) purgeKeys(keys []BpfLpmIpKeySt) error {
	var errors []error
	objs := infc.objs

	// Delete all keys that should be deleted.
	for _, keyToDelete := range keys {
		klog.Infof("Purging key %v", keyToDelete)
		err := objs.BpfMaps.IngressNodeFirewallTableMap.Delete(keyToDelete)
		if err != nil {
			errors = append(errors, err)
		}
	}
	if len(errors) > 0 {
		return apierrors.NewAggregate(errors)
	}
	return nil
}
