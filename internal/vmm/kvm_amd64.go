//go:build linux && amd64

package vmm

// x86-64 KVM backend: boots a vmlinux ELF via the 64-bit boot protocol
// (identity-mapped long mode, rsi = zero page), with the in-kernel irqchip
// (PIC+IOAPIC) and PIT, a port-I/O 16550 console, and virtio-mmio devices
// declared on the kernel cmdline.
//
// SMP: all vCPUs are created up front. APs stay in KVM_MP_STATE_UNINITIALIZED
// and their KVM_RUN blocks in-kernel until the BSP's smpboot sends
// INIT/SIPI via the in-kernel LAPIC; the guest trampoline does the rest.

import (
	"encoding/binary"
	"fmt"
	"github.com/ejpir/gantry/internal/gutil"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// ---- x86-64 KVM ioctl numbers ----------------------------------------------
const (
	kvmGetRegs           = 0x8090AE81 // _IOR(0xAE, 0x81, struct kvm_regs)
	kvmSetRegs           = 0x4090AE82 // _IOW (0xAE, 0x82, struct kvm_regs)
	kvmGetSregs          = 0x8138AE83 // _IOR(0xAE, 0x83, struct kvm_sregs)
	kvmSetSregs          = 0x4138AE84 // _IOW (0xAE, 0x84, struct kvm_sregs)
	kvmCreateIrqchip     = 0xAE60     // _IO (0xAE, 0x60)
	kvmCreatePit2        = 0x4040AE77 // _IOW (0xAE, 0x77, struct kvm_pit_config)
	kvmGetSupportedCpuid = 0xC008AE05 // _IOWR(0xAE, 0x05, struct kvm_cpuid2)
	kvmSetCpuid2         = 0x4008AE90 // _IOW (0xAE, 0x90, struct kvm_cpuid2)
)

// ---- UAPI structs (x86-64) --------------------------------------------------

type kvmRegs struct {
	rax, rbx, rcx, rdx uint64
	rsi, rdi, rsp, rbp uint64
	r8, r9, r10, r11   uint64
	r12, r13, r14, r15 uint64
	rip, rflags        uint64
}

type kvmSegment struct {
	base     uint64
	limit    uint32
	selector uint16
	typ      uint8
	present  uint8
	dpl      uint8
	db       uint8
	s        uint8
	l        uint8
	g        uint8
	avl      uint8
	unusable uint8
	pad      uint8
}

type kvmDTable struct {
	base  uint64
	limit uint16
	pad   [3]uint16
}

type kvmSRegs struct {
	cs, ds, es, fs, gs, ss kvmSegment
	tr, ldt                kvmSegment
	gdt, idt               kvmDTable
	cr0, cr2, cr3, cr4     uint64
	cr8                    uint64
	efer                   uint64
	apicBase               uint64
	intrBitmap             [4]uint64
}

type kvmCPUIDEntry2 struct {
	function uint32
	index    uint32
	flags    uint32
	eax      uint32
	ebx      uint32
	ecx      uint32
	edx      uint32
	pad      [3]uint32
}

type kvmCPUID2 struct {
	nent    uint32
	pad     uint32
	entries [256]kvmCPUIDEntry2
}

type kvmPitConfig struct {
	flags uint32
	pad   [15]uint32
}

// ---- backend ---------------------------------------------------------------

type kvmX86Backend struct {
	kvm   *kvmFile
	vmFD  uintptr
	vcpus []*kvmVCPU
	m     *Machine
}

// runGuest boots the prepared machine under KVM (entry point for main).
type kvmX86Platform struct{}

func (kvmX86Platform) run(m *Machine) error {
	if m.arch != "amd64" {
		return fmt.Errorf("KVM x86-64 backend can only boot x86-64 kernels (got %s)", m.arch)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	k, err := openKVM()
	if err != nil {
		return err
	}
	vmFD, err := k.createVM()
	if err != nil {
		k.Close()
		return fmt.Errorf("KVM_CREATE_VM: %w", err)
	}
	b := &kvmX86Backend{kvm: k, vmFD: vmFD, m: m}

	if err := ioctl(vmFD, kvmCreateIrqchip, nil); err != nil {
		return fmt.Errorf("KVM_CREATE_IRQCHIP: %w", err)
	}
	pit := kvmPitConfig{} // flags=0: PIT present, no speaker passthrough
	if err := ioctl(vmFD, kvmCreatePit2, unsafe.Pointer(&pit)); err != nil {
		return fmt.Errorf("KVM_CREATE_PIT2: %w", err)
	}

	reg := kvmUserspaceMemoryRegion{
		slot:          0,
		guestPhysAddr: 0,
		memorySize:    uint64(len(m.ram)),
		userspaceAddr: uint64(uintptr(unsafe.Pointer(&m.ram[0]))),
	}
	if err := ioctl(vmFD, kvmSetUserMemoryRegion, unsafe.Pointer(&reg)); err != nil {
		return fmt.Errorf("KVM_SET_USER_MEMORY_REGION: %w", err)
	}

	// Host CPUID (incl. KVM paravirt leaves: kvm-clock, ...) for all vCPUs.
	cpuid := &kvmCPUID2{nent: 256}
	if err := ioctl(k.fd, kvmGetSupportedCpuid, unsafe.Pointer(cpuid)); err != nil {
		return fmt.Errorf("KVM_GET_SUPPORTED_CPUID: %w", err)
	}
	if int(cpuid.nent) > len(cpuid.entries) {
		return fmt.Errorf("KVM_GET_SUPPORTED_CPUID: nent=%d exceeds buffer", cpuid.nent)
	}

	sz, _, errno := syscall.Syscall(syscall.SYS_IOCTL, k.fd, kvmGetVcpuMmapSize, 0)
	if errno != 0 {
		return fmt.Errorf("KVM_GET_VCPU_MMAP_SIZE: %w", errno)
	}
	for i := 0; i < m.vcpus; i++ {
		r, _, errno := syscall.Syscall(syscall.SYS_IOCTL, vmFD, kvmCreateVcpu, uintptr(i))
		if errno != 0 {
			return fmt.Errorf("KVM_CREATE_VCPU(%d): %w", i, errno)
		}
		vc := &kvmVCPU{id: i, fd: r}
		if err := ioctl(vc.fd, kvmSetCpuid2, unsafe.Pointer(cpuid)); err != nil {
			return fmt.Errorf("KVM_SET_CPUID2(%d): %w", i, err)
		}
		runBuf, err := syscall.Mmap(int(vc.fd), 0, int(sz),
			syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
		if err != nil {
			return fmt.Errorf("mmap kvm_run(%d): %w", i, err)
		}
		vc.run = kvmRunStruct{data: runBuf}
		b.vcpus = append(b.vcpus, vc)
	}

	m.irqLine = func(irq int, level bool) {
		il := kvmIRQLevel{irq: uint32(irq)}
		if level {
			il.level = 1
		}
		_ = ioctl(vmFD, kvmIRQLine, unsafe.Pointer(&il)) // best effort
	}

	for _, vc := range b.vcpus[1:] {
		// APs: KVM_RUN blocks in-kernel (mp_state UNINITIALIZED) until the
		// guest smpboot delivers INIT/SIPI. No register setup needed —
		// SIPI provides the real-mode start state.
		go func(vc *kvmVCPU) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if err := b.runVCPULoop(vc); err != nil {
				fmt.Fprintf(os.Stderr, "\n[cpu%d] run loop: %v\n", vc.id, err)
			}
		}(vc)
	}
	return b.bootLoop()
}

// bootLoop puts the BSP into 64-bit mode at the kernel entry and runs it.
func (b *kvmX86Backend) bootLoop() error {
	m := b.m
	vc := b.vcpus[0]

	// GET -> modify -> SET, so KVM's reset values survive for fields we
	// don't touch (APIC base, interrupt bitmap) and, critically, so TR/LDT
	// stay marked unusable: a zeroed segment (present=0, unusable=0) is
	// architecturally invalid and VMX refuses entry (KVM_EXIT_FAIL_ENTRY).
	sregs := kvmSRegs{}
	if err := ioctl(vc.fd, kvmGetSregs, unsafe.Pointer(&sregs)); err != nil {
		return fmt.Errorf("KVM_GET_SREGS: %w", err)
	}
	sregs.cr3 = x86PML4
	sregs.cr4 = 0x20       // PAE
	sregs.cr0 = 0x80010033 // PG|WP|NE|ET|MP|PE
	sregs.efer = 0x500     // LME|LMA
	sregs.cs = kvmSegment{base: 0, limit: 0xffffffff, selector: 0x10,
		typ: 0xb, present: 1, s: 1, l: 1, g: 1}
	data := kvmSegment{base: 0, limit: 0xffffffff, selector: 0x18,
		typ: 0x3, present: 1, s: 1, g: 1}
	sregs.ds, sregs.es, sregs.fs, sregs.gs, sregs.ss = data, data, data, data, data
	sregs.gdt = kvmDTable{base: x86GDT, limit: 4*8 - 1}
	sregs.idt = kvmDTable{base: 0, limit: 0xffff}
	if err := ioctl(vc.fd, kvmSetSregs, unsafe.Pointer(&sregs)); err != nil {
		return fmt.Errorf("KVM_SET_SREGS: %w", err)
	}
	regs := kvmRegs{
		rip:    m.entry,
		rsi:    x86ZeroPage, // -> struct boot_params
		rsp:    x86StackTop - 0x10,
		rflags: 0x2,
	}
	if err := ioctl(vc.fd, kvmSetRegs, unsafe.Pointer(&regs)); err != nil {
		return fmt.Errorf("KVM_SET_REGS: %w", err)
	}

	fmt.Printf("booting guest under KVM/x86-64 (%d vCPU max)\n", m.vcpus)
	fmt.Println("------------------------------------------------")

	if m.consoleStdin {
		go m.x86.uartIO.stdinPump(m.stdinDone)
		defer close(m.stdinDone)
	}
	return b.runVCPULoop(vc)
}

func (b *kvmX86Backend) runVCPULoop(vc *kvmVCPU) error {
	m := b.m
	exitCount := 0
	for {
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, vc.fd, kvmRun, 0)
		if errno == syscall.EINTR || errno == syscall.EAGAIN {
			// EAGAIN: a parked AP (mp_state UNINITIALIZED) was kicked but
			// no INIT/SIPI arrived yet — go back to sleep. QEMU retries
			// EAGAIN the same way; a dead AP thread means the SIPI has no
			// runner and smpboot fails ("CPUx failed to report alive").
			continue
		}
		if errno != 0 {
			return fmt.Errorf("KVM_RUN: %w", errno)
		}
		if dbgIO && exitCount < 100 {
			exitCount++
			regs := kvmRegs{}
			_ = ioctl(vc.fd, kvmGetRegs, unsafe.Pointer(&regs))
			reason := vc.run.exitReason()
			extra := ""
			switch reason {
			case kvmExitIO:
				extra = fmt.Sprintf(" port=%#x dir=%d size=%d", vc.run.ioPort(), vc.run.ioDir(), vc.run.ioSize())
			case kvmExitMMIO:
				extra = fmt.Sprintf(" phys=%#x w=%v", vc.run.mmioPhys(), vc.run.mmioIsWrite())
			}
			fmt.Printf("[x86] cpu%d exit %d rip=%#x%s\n", vc.id, reason, regs.rip, extra)
		}
		switch vc.run.exitReason() {
		case kvmExitMMIO:
			phys := vc.run.mmioPhys()
			val := m.handleMMIO(vc.run.mmioIsWrite(), phys, vc.run.mmioData(), vc.run.mmioLen())
			if !vc.run.mmioIsWrite() {
				binary.LittleEndian.PutUint32(vc.run.mmioData(), val)
			}
		case kvmExitIO:
			if err := b.handleIO(vc); err != nil {
				return err
			}
		case kvmExitHLT:
			// Re-enter; KVM_RUN blocks until an interrupt is pending.
		case kvmExitShutdown:
			b.m.stdoutFlush()
			regs := kvmRegs{}
			_ = ioctl(vc.fd, kvmGetRegs, unsafe.Pointer(&regs))
			fmt.Println("\n------------------------------------------------")
			fmt.Printf("guest shutdown (triple fault) rip=%#x rax=%#x\n", regs.rip, regs.rax)
			return nil
		case kvmExitFailEntry:
			return fmt.Errorf("KVM_EXIT_FAIL_ENTRY hardware_reason=%d (vmx instr error)", gutil.LE64(vc.run.data[16:]))
		case kvmExitInternalError:
			return fmt.Errorf("KVM_EXIT_INTERNAL_ERROR suberror=%d", gutil.LE32(vc.run.data[32:]))
		default:
			// irq window, debug, hypercall: nothing to do, re-enter
		}
	}
}

// handleIO services one KVM_EXIT_IO: port reads/writes, incl. REP/string
// accesses (count > 1, data is a contiguous byte buffer).
func (b *kvmX86Backend) handleIO(vc *kvmVCPU) error {
	port := vc.run.ioPort()
	size := int(vc.run.ioSize())
	count := int(vc.run.ioCount())
	isWrite := vc.run.ioDir() != 0
	data := vc.run.ioData()
	if len(data) < size*count {
		return fmt.Errorf("short io data (port %#x)", port)
	}

	// Guest-initiated reset: treat as VM exit.
	if isWrite && (port == 0xcf9 || (port == 0x64 && data[0] == 0xfe)) {
		b.m.stdoutFlush()
		fmt.Println("\n------------------------------------------------")
		fmt.Println("guest rebooted (reset port); exiting")
		return ErrGuestReset
	}

	for i := 0; i < count; i++ {
		chunk := data[i*size:]
		if isWrite {
			var v uint32
			for j := 0; j < size && j < 4; j++ {
				v |= uint32(chunk[j]) << (8 * j)
			}
			b.m.handleIO(true, port, v, size)
		} else {
			v := b.m.handleIO(false, port, 0, size)
			for j := 0; j < size && j < 4; j++ {
				chunk[j] = byte(v >> (8 * j))
			}
		}
	}
	return nil
}

// platformBackend selects the hypervisor backend for this build target.
func platformBackend() backend { return kvmX86Platform{} }
