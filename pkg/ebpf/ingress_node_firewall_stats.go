package nodefw

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"log"
	"net"
	"strings"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../../bpf/ingress_node_firewall_kernel.c -- -I ../../bpf/headers -I/usr/include/x86_64-linux-gnu/

func IngressNodeFwStatsLoader(ifacesName []string) {
	// Load pre-compiled programs into the kernel.
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
		}
		// Attach the program.
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.IngresNodeFirewallProcess,
			Interface: iface.Index,
		})
		if err != nil {
			log.Fatalf("could not attach XDP program: %s", err)
		}
		defer l.Close()
		log.Printf("Attached IngressNode Firewall program to iface %q (index %d)", iface.Name, iface.Index)
	}

	s, err := formatMapContents(objs.IngressNodeFirewallStatsMap)
	if err != nil {
		log.Printf("Error reading map: %s", err)
	}
	log.Printf("Map contents:\n%s", s)
}

type Stats struct {
	Packets uint64
	Bytes   uint64
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key uint32
		val Stats
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		fmt.Printf("\t%d => %+v\n", key, val)
	}
	return sb.String(), iter.Err()
}
