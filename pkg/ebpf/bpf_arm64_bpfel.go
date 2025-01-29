// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64

package nodefwloader

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type BpfEventHdrSt struct {
	IfId      uint16
	RuleId    uint16
	Action    uint8
	Pad       uint8
	PktLength uint16
}

type BpfLpmIpKeySt struct {
	PrefixLen      uint32
	IngressIfindex uint32
	IpData         [16]uint8
}

type BpfRuleStatisticsSt struct {
	AllowStats struct {
		Packets uint64
		Bytes   uint64
	}
	DenyStats struct {
		Packets uint64
		Bytes   uint64
	}
}

type BpfRuleTypeSt struct {
	RuleId       uint32
	Protocol     uint8
	DstPortStart uint16
	DstPortEnd   uint16
	IcmpType     uint8
	IcmpCode     uint8
	Action       uint8
}

type BpfRulesValSt struct{ Rules [100]BpfRuleTypeSt }

// LoadBpf returns the embedded CollectionSpec for Bpf.
func LoadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Bpf: %w", err)
	}

	return spec, err
}

// LoadBpfObjects loads Bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*BpfObjects
//	*BpfPrograms
//	*BpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// BpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfSpecs struct {
	BpfProgramSpecs
	BpfMapSpecs
	BpfVariableSpecs
}

// BpfProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfProgramSpecs struct {
	TcxIngressNodeFirewallProcess *ebpf.ProgramSpec `ebpf:"tcx_ingress_node_firewall_process"`
	XdpIngressNodeFirewallProcess *ebpf.ProgramSpec `ebpf:"xdp_ingress_node_firewall_process"`
}

// BpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfMapSpecs struct {
	IngressNodeFirewallDbgMap        *ebpf.MapSpec `ebpf:"ingress_node_firewall_dbg_map"`
	IngressNodeFirewallEventsMap     *ebpf.MapSpec `ebpf:"ingress_node_firewall_events_map"`
	IngressNodeFirewallStatisticsMap *ebpf.MapSpec `ebpf:"ingress_node_firewall_statistics_map"`
	IngressNodeFirewallTableMap      *ebpf.MapSpec `ebpf:"ingress_node_firewall_table_map"`
}

// BpfVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfVariableSpecs struct {
	DebugLookup *ebpf.VariableSpec `ebpf:"debug_lookup"`
	Unused1     *ebpf.VariableSpec `ebpf:"unused1"`
}

// BpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfObjects struct {
	BpfPrograms
	BpfMaps
	BpfVariables
}

func (o *BpfObjects) Close() error {
	return _BpfClose(
		&o.BpfPrograms,
		&o.BpfMaps,
	)
}

// BpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfMaps struct {
	IngressNodeFirewallDbgMap        *ebpf.Map `ebpf:"ingress_node_firewall_dbg_map"`
	IngressNodeFirewallEventsMap     *ebpf.Map `ebpf:"ingress_node_firewall_events_map"`
	IngressNodeFirewallStatisticsMap *ebpf.Map `ebpf:"ingress_node_firewall_statistics_map"`
	IngressNodeFirewallTableMap      *ebpf.Map `ebpf:"ingress_node_firewall_table_map"`
}

func (m *BpfMaps) Close() error {
	return _BpfClose(
		m.IngressNodeFirewallDbgMap,
		m.IngressNodeFirewallEventsMap,
		m.IngressNodeFirewallStatisticsMap,
		m.IngressNodeFirewallTableMap,
	)
}

// BpfVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfVariables struct {
	DebugLookup *ebpf.Variable `ebpf:"debug_lookup"`
	Unused1     *ebpf.Variable `ebpf:"unused1"`
}

// BpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfPrograms struct {
	TcxIngressNodeFirewallProcess *ebpf.Program `ebpf:"tcx_ingress_node_firewall_process"`
	XdpIngressNodeFirewallProcess *ebpf.Program `ebpf:"xdp_ingress_node_firewall_process"`
}

func (p *BpfPrograms) Close() error {
	return _BpfClose(
		p.TcxIngressNodeFirewallProcess,
		p.XdpIngressNodeFirewallProcess,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_arm64_bpfel.o
var _BpfBytes []byte
