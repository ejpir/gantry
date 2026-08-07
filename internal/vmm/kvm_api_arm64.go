//go:build linux && arm64

package vmm

import "github.com/ejpir/gantry/internal/gutil"

// KVM API structures used only by the arm64 backend (vm_linux.go): VGIC
// device creation, device attributes, the one-reg interface, and the
// system-event exit decode. The x86 port-I/O exit fields live in
// kvm_io_amd64.go.

const (
	kvmSystemEventShutdown = 1
	kvmSystemEventReset    = 2
	kvmSystemEventCrash    = 3
)

type kvmCreateDeviceStruct struct {
	typ   uint32
	fd    uint32
	flags uint32
}

type kvmDeviceAttr struct {
	flags uint32
	group uint32
	attr  uint64
	addr  uint64
}

type kvmOneReg struct {
	id   uint64
	addr uint64
}

func (r kvmRunStruct) sysEventType() uint32 {
	return gutil.LE32(r.data[32:])
}
