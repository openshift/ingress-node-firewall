//go:build !cgo
// +build !cgo

package libxdploader

// Both the daemon and the main operator are in the same module.
// Therefore, the go compiler will build the libxdploader even for the main
// operator. In order to avoid this dependency, create a stub libxdploader
// that will be used for non-CGO compilation, and use build tags to compile
// the C dependencies only when CGO is used.

type (
	XdpProgram     interface{}
	XdpProgramOPts interface{}
	XdpOpenOpts    interface{}
	XdpAttachMode  uint32
)

func LoadXdpProgram(program, pinPath string) XdpProgram {
	return nil
}

func GetXdpProgramName(program XdpProgram) string {
	return ""
}

func GetXdpProgramFD(program XdpProgram) int {
	return 0
}

func FindXdpProgramFromFD(fd int) XdpProgram {
	return nil
}

func FindXdpProgramFromId(id uint) XdpProgram {
	return nil
}

func FindXdpProgramFromPin(pinPath string) XdpProgram {
	return nil
}

func CloseProgram(program XdpProgram) {
	return
}

func XdpProgramIsAttached(xdpProg XdpProgram, ifIndex int) XdpAttachMode {
	return 0
}

func XdpPinProgram(xdpProg XdpProgram, pinPath string) int {
	return 0
}

func XdpAttachProgram(xdpProg XdpProgram, ifIndex int) int {
	return 0
}

func XdpDetachProgram(xdpProg XdpProgram, ifIndex int) int {
	return 0
}
