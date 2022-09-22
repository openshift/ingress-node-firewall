//go:build cgo
// +build cgo

package libxdploader

// #cgo LDFLAGS: -lxdp -lbpf
// #include <bpf/libbpf.h>
// #include <xdp/libxdp.h>
import "C"
import "unsafe"

type (
	XdpProgram     *C.struct_xdp_program
	XdpProgramOPts *C.struct_xdp_program_opts
	XdpOpenOpts    C.struct_bpf_object_open_opts
	XdpAttachMode  uint32
)

const (
	xdpUnspecMode                XdpAttachMode = 0
	xdpNativeMode                XdpAttachMode = 1
	xdpSkbMode                   XdpAttachMode = 2
	xdpHWMode                    XdpAttachMode = 3
	ingressNodeFirewwallEventMap               = "ingress_node_firewall_events_map"
)

// LoadXdpProgram is a wrapper around libxdp's xdp_program__open_file(), it takes XDP program name and pinPath,
// it returns a pointer to xdp_program structure.
// It also sets the max cpu for event map to work around compatability issue between Cilium and libbpf libraries.
func LoadXdpProgram(program, pinPath string) XdpProgram {
	var opts XdpOpenOpts
	opts.sz = C.ulong(unsafe.Sizeof(opts))
	opts.pin_root_path = C.CString(pinPath)
	xdpProgram := (XdpProgram)(C.xdp_program__open_file(C.CString(program), nil, (*C.struct_bpf_object_open_opts)(&opts)))
	bpfMap := C.bpf_object__find_map_by_name(getBpfObjFromProgram(xdpProgram), C.CString(ingressNodeFirewwallEventMap))
	if bpfMap == nil {
		return nil
	}
	C.bpf_map__set_max_entries(bpfMap, C.uint(C.libbpf_num_possible_cpus()))
	return xdpProgram
}

// getBpfObjFromProgram is a wrapper around libxdp's getBpfObjFromProgram() it takes xdpProgram and returns pointer to bpf object.
func getBpfObjFromProgram(program XdpProgram) *C.struct_bpf_object {
	return C.xdp_program__bpf_obj(program)
}

// GetXdpProgramName is a wrapper around libxdp's xdp_program__name() it takes xdpProgram and returns the XDP program name.
func GetXdpProgramName(program XdpProgram) string {
	return C.GoString(C.xdp_program__name(program))
}

// GetXdpProgramFD is a wrapper around libxdp's xdp_program__fd() it takes an xdpProgram and returns the XDP program FD.
func GetXdpProgramFD(program XdpProgram) int {
	return (int)(C.xdp_program__fd(program))
}

// FindXdpProgramFromFD is a wrapper around libxdp's xdp_program__from_fd() it takes an FD and returns xdpProgram with matching FD.
func FindXdpProgramFromFD(fd int) XdpProgram {
	return C.xdp_program__from_fd(C.int(fd))
}

// FindXdpProgramFromID is a wrapper around libxdp's xdp_program__from_id() it takes an XDP program ID, and returns xdpProgram with matching ID.
func FindXdpProgramFromID(id uint) XdpProgram {
	return C.xdp_program__from_id(C.uint(id))
}

// FindXdpProgramFromPin is a wrapper around libxdp's xdp_program__from_pin() it takes pinPath, and returns xdpProgram in that pinPath.
func FindXdpProgramFromPin(pinPath string) XdpProgram {
	return C.xdp_program__from_pin(C.CString(pinPath))
}

// CloseProgram is a wrapper around libxdp's xdp_program__close(), it will close the xdpProgram and free all allocated resources.
func CloseProgram(program XdpProgram) {
	C.xdp_program__close(program)
}

// XdpProgramIsAttached is a wrapper around libxdp's xdp_program__is_attached, for specific XDP program and interface it returns the attachment mode.
func XdpProgramIsAttached(xdpProg XdpProgram, ifIndex int) XdpAttachMode {
	return (XdpAttachMode)(C.xdp_program__is_attached(xdpProg, C.int(ifIndex)))
}

// XdpPinProgram is a wrapper around libxdp's xdp_program__pin, it takes an xdpProgram and pinPath and t will pin the XDP program to the specified path.
// it will return the return code from xdp_program__pin().
func XdpPinProgram(xdpProg XdpProgram, pinPath string) int {
	return (int)(C.xdp_program__pin(xdpProg, C.CString(pinPath)))
}

// XdpAttachProgram is a wrapper around libxdp's xdp_program__attach(), it takes an xdpProgram and interface and it will attach
// the XDP program to the specified interface and returns the return code from xdp_program__attach().
func XdpAttachProgram(xdpProg XdpProgram, ifIndex int) int {
	return (int)(C.xdp_program__attach(xdpProg, C.int(ifIndex), uint32(xdpNativeMode), 0))
}

// XdpDetachProgram is a wrapper around libxdp's xdp_program__detach(), it takes an xdpProgram and interface and it will detach
// the XDP program from the specified interface and returns the return code from xdp_program__detach().
func XdpDetachProgram(xdpProg XdpProgram, ifIndex int) int {
	return (int)(C.xdp_program__detach(xdpProg, C.int(ifIndex), uint32(xdpNativeMode), 0))
}
