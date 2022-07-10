package nodefw

import (
	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	ingressnodefwiov1alpha1 "ingress-node-firewall/api/v1alpha1"
	"k8s.io/klog"
	"log"
	"net"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../../bpf/ingress_node_firewall_kernel.c -- -I ../../bpf/headers -I/usr/include/x86_64-linux-gnu/
func IngressNodeFwRulesLoader(ingFireWallConfig ingressnodefwiov1alpha1.IngressNodeFirewallRules) error {
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

	k, rules, err := makeIngressFwRulesMap(ingFireWallConfig)
	if err != nil {
		klog.Fatalf("Failed to create map info: %v", err)
		return err
	}

	if _, err := objs.bpfMaps.IngressNodeFirewallTableMap.BatchUpdate(k, rules, &cebpf.BatchOptions{}); err != nil {
		klog.Fatalf("Failed Loading service entries: %v", err)
		return err
	}
	return nil
}

func makeIngressFwRulesMap(ingFireWallConfig ingressnodefwiov1alpha1.IngressNodeFirewallRules) (key bpfBpfLpmIpKeySt, rules bpfRulesValSt, err error) {
	k := bpfBpfLpmIpKeySt{}
	r := bpfRulesValSt{}
	// TODO
	return k, r, nil
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
