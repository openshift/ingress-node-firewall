package nodefw

import (
	"github.com/cilium/ebpf/link"
	"log"
	"net"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS  bpf ./src/ingress_node_firewall_kernel.c -- -I ./headers -I/usr/include/x86_64-linux-gnu/

func IngressNodeFwRulesLoader(key bpfBpfLpmIpKeySt , rules bpfRulesValSt) error {
	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
		return err
	}
	defer objs.Close()
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