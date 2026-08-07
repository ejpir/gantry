//go:build linux

// Package main implements a minimal virtual machine monitor (VMM) for
// Linux/aarch64 using the raw KVM API — the same interface the
// reference VMM (rust-vmm style) uses, just without any frameworks.
package vmm

import (
	"fmt"
	"github.com/ejpir/gantry/internal/gutil"
	"syscall"
	"unsafe"
)

// ---- KVM ioctl numbers (arch-neutral) -------------------------------------
// KVM ioctls are _IO*/_IOR*/_IOW* encoded with the KVM ioctl base 0xAE.
// Arch-specific numbers live in kvm_arm64.go / kvm_amd64.go.
const (
	kvmGetAPIVersion   = 0xAE00 // _IO(0xAE, 0x00)
	kvmCreateVM        = 0xAE01 // _IO(0xAE, 0x01)
	kvmGetVcpuMmapSize = 0xAE04 // _IO(0xAE, 0x04)
	kvmCreateVcpu      = 0xAE41 // _IO(0xAE, 0x41)
	kvmRun             = 0xAE80 // _IO(0xAE, 0x80)

	kvmSetUserMemoryRegion = 0x4020AE46 // _IOW (0xAE, 0x46, 32)
	kvmCreateDevice        = 0xC00CAEE0 // _IOWR(0xAE, 0xE0, 12)
	kvmSetDeviceAttr       = 0x4018AEE1 // _IOW (0xAE, 0xE1, 24)
	kvmIRQLine             = 0x4008AE61 // _IOW (0xAE, 0x61, 8)
)

// ---- KVM constants (arch-neutral) ------------------------------------------
const (
	kvmExitIO            = 2
	kvmExitHLT           = 5
	kvmExitMMIO          = 6
	kvmExitShutdown      = 8
	kvmExitFailEntry     = 9
	kvmExitInternalError = 17
	kvmExitSystemEvent   = 24
)

func ioctl(fd uintptr, req uint, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

// ---- structs matching the UAPI layout (little-endian) ----------------------

type kvmUserspaceMemoryRegion struct {
	slot          uint32
	flags         uint32
	guestPhysAddr uint64
	memorySize    uint64
	userspaceAddr uint64
}

// (kvmVcpuInit is arm64-only; see kvm_arm64.go)

type kvmIRQLevel struct {
	irq   uint32
	level uint32
}

// kvmRunExit decodes fields from the mmap'd struct kvm_run.
// Offsets: exit_reason @8 (u32, then request_interrupt_window @12); union @32:
//
//	io:          direction @32 (u8), size @33 (u8), port @34 (u16), count @36 (u32), data_offset @40 (u64)
//	mmio:        phys_addr @32 (u64), data @40 ([8]u8), len @48 (u32), is_write @52 (u8)
//	system_event: type @32 (u32), flags @40 (u64)
type kvmRunStruct struct{ data []byte }

func (r kvmRunStruct) exitReason() uint64 { return uint64(gutil.LE32(r.data[8:])) }
func (r kvmRunStruct) mmioPhys() uint64   { return gutil.LE64(r.data[32:]) }
func (r kvmRunStruct) mmioData() []byte   { return r.data[40:48] }
func (r kvmRunStruct) mmioLen() uint32    { return gutil.LE32(r.data[48:]) }
func (r kvmRunStruct) mmioIsWrite() bool  { return r.data[52] != 0 }

// ---- thin wrappers ---------------------------------------------------------

// kvmVCPU is one virtual CPU: its fd, mmap'd kvm_run area, and thread.
type kvmVCPU struct {
	id  int
	fd  uintptr
	run kvmRunStruct
}

type kvmFile struct{ fd uintptr }

func openKVM() (*kvmFile, error) {
	fd, err := syscall.Open("/dev/kvm", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/kvm: %w (need --device /dev/kvm or host access)", err)
	}
	k := &kvmFile{fd: uintptr(fd)}
	v, err := k.getAPIVersion()
	if err != nil {
		k.Close()
		return nil, fmt.Errorf("KVM_GET_API_VERSION: %w", err)
	}
	if v != 12 {
		k.Close()
		return nil, fmt.Errorf("unexpected KVM API version %d", v)
	}
	return k, nil
}

func (k *kvmFile) Close() { _ = syscall.Close(int(k.fd)) }

func (k *kvmFile) getAPIVersion() (int, error) {
	r, _, errno := syscall.Syscall(syscall.SYS_IOCTL, k.fd, kvmGetAPIVersion, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

func (k *kvmFile) createVM() (uintptr, error) {
	r, _, errno := syscall.Syscall(syscall.SYS_IOCTL, k.fd, kvmCreateVM, 0)
	if errno != 0 {
		return 0, errno
	}
	return r, nil
}
