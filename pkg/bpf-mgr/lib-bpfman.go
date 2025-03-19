package bpf_mgr

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/openshift/ingress-node-firewall/api/v1alpha1"

	bpfmaniov1alpha1 "github.com/bpfman/bpfman-operator/apis/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	debugLookup                = "debug_lookup" // constant defined in kernel hook to enable LongPrefixMatch "LPM" lookup
	ingressNodeFirewallApp     = "ingress-node-firewall"
	ingressNodeFirewallXDPHook = "xdp_ingress_node_firewall_process"
	ingressNodeFirewallTCXHook = "tcx_ingress_node_firewall_process"
	ingressDirection           = "ingress"
	ingressNodeFirewallBCImage = "quay.io/bpfman-bytecode/ingress-node-firewall:latest"
)

// BpfmanAttachNodeFirewall Creates BpfmanApplication object with all required ebpf hooks and attaches them using bpfman manager
func BpfmanAttachNodeFirewall(ctx context.Context, client client.Client, obj *v1alpha1.IngressNodeFirewall, dbg bool) error {
	return bpfmanCreateNodeFirewallApplication(ctx, client, obj, dbg, false)
}

// BpfmanDetachNodeFirewall Creates BpfmanApplication object with all required ebpf hooks and detaches them using bpfman manager
func BpfmanDetachNodeFirewall(ctx context.Context, client client.Client, obj *v1alpha1.IngressNodeFirewall, dbg bool) error {
	return bpfmanCreateNodeFirewallApplication(ctx, client, obj, dbg, true)
}

func bpfmanCreateNodeFirewallApplication(ctx context.Context, c client.Client, obj *v1alpha1.IngressNodeFirewall, dbg, isDelete bool) error {
	var err error
	bpfApp := bpfmaniov1alpha1.ClusterBpfApplication{
		ObjectMeta: v1.ObjectMeta{
			Name: ingressNodeFirewallApp,
		},
		TypeMeta: v1.TypeMeta{
			Kind: "BpfApplication",
		},
	}

	key := client.ObjectKey{Name: ingressNodeFirewallApp}

	if isDelete {
		err := c.Get(ctx, key, &bpfApp)
		if err != nil {
			return fmt.Errorf("failed to get BpfApplication: %v", err)
		}

		err = deleteBpfApplication(ctx, c, &bpfApp)
		if err != nil {
			return fmt.Errorf("failed to delete BpfApplication: %v", err)
		}
		return nil
	}

	err = c.Get(ctx, key, &bpfApp)
	if err != nil {
		if errors.IsNotFound(err) {
			prepareBpfApplication(&bpfApp, obj, dbg)
			err = createBpfApplication(ctx, c, &bpfApp, obj.Name)
			if err != nil {
				return fmt.Errorf("failed to create BpfApplication: %v for obj: %s", err, obj.Name)
			}
		} else {
			return fmt.Errorf("failed to get BpfApplication: %v for obj: %s", err, obj.Name)
		}
	} else {
		// object exists repopulate it with the new configuration and update it
		prepareBpfApplication(&bpfApp, obj, dbg)
		err = updateBpfApplication(ctx, c, &bpfApp, obj.Name)
		if err != nil {
			return fmt.Errorf("failed to update BpfApplication: %v for obj: %s", err, obj.Name)
		}
	}

	return err
}

func prepareBpfApplication(bpfApp *bpfmaniov1alpha1.ClusterBpfApplication, obj *v1alpha1.IngressNodeFirewall, dbg bool) {
	interfaces := obj.Spec.Interfaces

	debug := make([]byte, 4)
	var value uint32

	if dbg {
		value = 1
	}
	binary.NativeEndian.PutUint32(debug, value)
	bpfApp.Spec.BpfAppCommon.GlobalData = map[string][]byte{
		debugLookup: debug,
	}

	bpfApp.Labels = map[string]string{
		"app": ingressNodeFirewallApp,
	}
	bpfApp.Spec.NodeSelector = obj.Spec.NodeSelector

	bpfApp.Spec.BpfAppCommon.ByteCode = bpfmaniov1alpha1.ByteCodeSelector{
		Image: &bpfmaniov1alpha1.ByteCodeImage{
			Url:             ingressNodeFirewallBCImage,
			ImagePullPolicy: bpfmaniov1alpha1.PullIfNotPresent,
		},
	}
	bpfApp.Spec.Programs = []bpfmaniov1alpha1.ClBpfApplicationProgram{
		{
			Type: bpfmaniov1alpha1.ProgTypeXDP,
			Name: ingressNodeFirewallXDPHook,
			XDP: &bpfmaniov1alpha1.ClXdpProgramInfo{
				Links: []bpfmaniov1alpha1.ClXdpAttachInfo{
					{
						InterfaceSelector: bpfmaniov1alpha1.InterfaceSelector{Interfaces: &interfaces},
					},
				},
			},
		},
		{
			Type: bpfmaniov1alpha1.ProgTypeTCX,
			Name: ingressNodeFirewallTCXHook,
			TCX: &bpfmaniov1alpha1.ClTcxProgramInfo{
				Links: []bpfmaniov1alpha1.ClTcxAttachInfo{
					{
						InterfaceSelector: bpfmaniov1alpha1.InterfaceSelector{Interfaces: &interfaces},
						Direction:         ingressDirection,
					},
				},
			},
		},
	}
}

func deleteBpfApplication(ctx context.Context, c client.Client, bpfApp *bpfmaniov1alpha1.ClusterBpfApplication) error {
	klog.Info("Deleting BpfApplication Object")
	return c.Delete(ctx, bpfApp)
}

func createBpfApplication(ctx context.Context, c client.Client, bpfApp *bpfmaniov1alpha1.ClusterBpfApplication, objName string) error {
	for _, p := range bpfApp.Spec.Programs {
		switch p.Type {
		case bpfmaniov1alpha1.ProgTypeXDP:
			klog.Infof("Creating BpfApplication for XDP Prog: %v for INFW obj: %v", *p.XDP, objName)
		case bpfmaniov1alpha1.ProgTypeTCX:
			klog.Infof("Creating BpfApplication for TCX Prog: %v for INFW obj: %v", *p.TCX, objName)
		}
	}
	return c.Create(ctx, bpfApp)
}

func updateBpfApplication(ctx context.Context, c client.Client, bpfApp *bpfmaniov1alpha1.ClusterBpfApplication, objName string) error {
	for _, p := range bpfApp.Spec.Programs {
		switch p.Type {
		case bpfmaniov1alpha1.ProgTypeXDP:
			klog.Infof("Updating BpfApplication for XDP Prog: %v for INFW obj: %v", *p.XDP, objName)
		case bpfmaniov1alpha1.ProgTypeTCX:
			klog.Infof("Updating BpfApplication for TCX Prog: %v for INFW obj: %v", *p.TCX, objName)
		}
	}
	return c.Update(ctx, bpfApp)
}
