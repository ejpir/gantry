//go:build linux

// Package main implements a minimal virtual machine monitor (VMM) for
// Linux/aarch64 using the raw KVM API — the same interface the
// reference VMM (rust-vmm style) uses, just without any frameworks.
package vmm

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/ejpir/gantry/internal/gutil"
	"golang.org/x/sys/unix"
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
	id      int
	fd      uintptr
	run     kvmRunStruct
	hostTID atomic.Int64
}

// kvmFile owns the /dev/kvm handle: either a raw fd it opened itself,
// or a pre-opened *os.File handed over by the supervisor (confined
// worker — the file field keeps single ownership so Close never
// double-closes).
type kvmFile struct {
	fd       uintptr
	file     *os.File
	close    sync.Once
	closeErr error
}

// takeKVM transfers the pre-opened hypervisor descriptor from the Machine to
// the Linux backend. A nil descriptor is valid and means open /dev/kvm.
func (m *Machine) takeKVM() (*os.File, error) {
	m.resourceMu.Lock()
	defer m.resourceMu.Unlock()
	if m.lifecycle == machineStopping || m.lifecycle == machineClosed {
		return nil, errMachineClosed
	}
	if m.lifecycle != machineRunning {
		return nil, errors.New("vmm: KVM descriptor requested outside Run")
	}
	fd := m.kvmFD
	m.kvmFD = nil
	return fd, nil
}

// openKVM validates the KVM API version on the device. When dev is nil
// it opens /dev/kvm by path (monolithic); otherwise it adopts the
// pre-opened descriptor (confined worker — its private /dev is empty).
func openKVM(dev *os.File) (*kvmFile, error) {
	var k *kvmFile
	if dev != nil {
		k = &kvmFile{fd: dev.Fd(), file: dev}
	} else {
		fd, err := syscall.Open("/dev/kvm", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("open /dev/kvm: %w (need --device /dev/kvm or host access)", err)
		}
		k = &kvmFile{fd: uintptr(fd)}
	}
	v, err := k.getAPIVersion()
	if err != nil {
		_ = k.Close()
		return nil, fmt.Errorf("KVM_GET_API_VERSION: %w", err)
	}
	if v != 12 {
		_ = k.Close()
		return nil, fmt.Errorf("unexpected KVM API version %d", v)
	}
	return k, nil
}

func (k *kvmFile) Close() error {
	k.close.Do(func() {
		if k.file != nil {
			k.closeErr = k.file.Close()
			return
		}
		k.closeErr = syscall.Close(int(k.fd))
	})
	return k.closeErr
}

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

// kvmMachineResources owns every kernel object created for one VM. It is
// assembled before vCPU execution begins, then transferred wholesale to the
// Machine. Close first stops all run loops, then releases mmaps and descriptors
// in dependency order. The once guard makes concurrent Machine.Close calls and
// Run's final cleanup converge on exactly one teardown.
type kvmMachineResources struct {
	kvm *kvmFile

	vmFD    uintptr
	vmOpen  bool
	gicFD   uintptr
	gicOpen bool
	vcpus   []*kvmVCPU

	stopping  atomic.Bool
	runWG     sync.WaitGroup
	unstarted atomic.Int32
	close     sync.Once
	closeErr  error
}

func (r *kvmMachineResources) prepareVCPURuns() {
	count := len(r.vcpus)
	r.unstarted.Store(int32(count))
	r.runWG.Add(count)
}

// abandonVCPURuns releases every reservation that no run goroutine claimed.
// It races safely with newly scheduled goroutines: either the goroutine owns
// the reservation and calls Done, or this method owns it and the goroutine
// returns before touching resources that teardown may release.
func (r *kvmMachineResources) abandonVCPURuns() {
	for range int(r.unstarted.Swap(0)) {
		r.runWG.Done()
	}
}

func (r *kvmMachineResources) runVCPU(vc *kvmVCPU, run func(*kvmVCPU) error) error {
	for {
		remaining := r.unstarted.Load()
		if remaining == 0 {
			return nil
		}
		if r.unstarted.CompareAndSwap(remaining, remaining-1) {
			break
		}
	}
	defer r.runWG.Done()
	vc.hostTID.Store(int64(syscall.Gettid()))
	defer vc.hostTID.Store(0)
	if r.stopping.Load() {
		return nil
	}
	return run(vc)
}

func (r *kvmMachineResources) Close() error {
	r.close.Do(func() {
		r.stopping.Store(true)
		var errs []error
		for _, vc := range r.vcpus {
			// immediate_exit is byte 1 of struct kvm_run. Store the first word
			// atomically so the race detector and concurrent run-loop checks see
			// one stop transition; byte 0 (request_interrupt_window) becomes 0.
			if len(vc.run.data) >= 4 {
				atomic.StoreUint32((*uint32)(unsafe.Pointer(&vc.run.data[0])), 1<<8)
			}
			if tid := int(vc.hostTID.Load()); tid != 0 {
				if err := unix.Tgkill(os.Getpid(), tid, syscall.SIGURG); err != nil && !errors.Is(err, syscall.ESRCH) {
					errs = append(errs, fmt.Errorf("interrupt KVM vCPU %d: %w", vc.id, err))
				}
			}
		}
		r.runWG.Wait()

		for _, vc := range r.vcpus {
			if len(vc.run.data) != 0 {
				if err := syscall.Munmap(vc.run.data); err != nil {
					errs = append(errs, fmt.Errorf("unmap KVM vCPU %d run state: %w", vc.id, err))
				}
				vc.run.data = nil
			}
			if err := syscall.Close(int(vc.fd)); err != nil {
				errs = append(errs, fmt.Errorf("close KVM vCPU %d: %w", vc.id, err))
			}
		}
		if r.gicOpen {
			if err := syscall.Close(int(r.gicFD)); err != nil {
				errs = append(errs, fmt.Errorf("close KVM GIC: %w", err))
			}
			r.gicOpen = false
		}
		if r.vmOpen {
			if err := syscall.Close(int(r.vmFD)); err != nil {
				errs = append(errs, fmt.Errorf("close KVM VM: %w", err))
			}
			r.vmOpen = false
		}
		if r.kvm != nil {
			if err := r.kvm.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close KVM device: %w", err))
			}
			r.kvm = nil
		}
		r.closeErr = errors.Join(errs...)
	})
	return r.closeErr
}
