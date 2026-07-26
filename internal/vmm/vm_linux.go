//go:build linux && arm64

package vmm

import (
	"encoding/binary"
	"fmt"
	"gantry/internal/gutil"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// kvmBackend is the Linux/KVM implementation of the hypervisor backend.
type kvmBackend struct {
	kvm   *kvmFile
	vmFD  uintptr
	vcpus []*kvmVCPU
	m     *Machine
}

// runGuest boots the prepared machine under KVM (entry point for main).
type kvmARM64Platform struct{}

func (kvmARM64Platform) run(m *Machine) error {
	// Pin the run loop to one OS thread (vCPU-run loops should be
	// thread-affine; critical on HVF, good hygiene on KVM).
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
	b := &kvmBackend{kvm: k, vmFD: vmFD, m: m}

	// register guest RAM
	reg := kvmUserspaceMemoryRegion{
		slot:          0,
		guestPhysAddr: ramBase,
		memorySize:    uint64(len(m.ram)),
		userspaceAddr: uint64(uintptr(unsafe.Pointer(&m.ram[0]))),
	}
	if err := ioctl(vmFD, kvmSetUserMemoryRegion, unsafe.Pointer(&reg)); err != nil {
		return fmt.Errorf("KVM_SET_USER_MEMORY_REGION: %w", err)
	}

	if err := b.createGIC(); err != nil {
		return err
	}

	sz, _, errno := syscall.Syscall(syscall.SYS_IOCTL, k.fd, kvmGetVcpuMmapSize, 0)
	if errno != 0 {
		return fmt.Errorf("KVM_GET_VCPU_MMAP_SIZE: %w", errno)
	}
	// Create all vCPUs up front; secondaries start powered off and the
	// kernel brings them up with in-kernel PSCI CPU_ON.
	for i := 0; i < m.vcpus; i++ {
		r, _, errno := syscall.Syscall(syscall.SYS_IOCTL, vmFD, kvmCreateVcpu, uintptr(i))
		if errno != 0 {
			return fmt.Errorf("KVM_CREATE_VCPU(%d): %w", i, errno)
		}
		vc := &kvmVCPU{id: i, fd: r}
		vi := kvmVcpuInit{target: kvmArmTargetGenericV8}
		vi.features[0] = (1 << kvmArmVcpuPowerOff) | (1 << kvmArmVcpuPSCI02)
		if err := ioctl(vc.fd, kvmArmVcpuInit, unsafe.Pointer(&vi)); err != nil {
			return fmt.Errorf("KVM_ARM_VCPU_INIT(%d): %w", i, err)
		}
		runBuf, err := syscall.Mmap(int(vc.fd), 0, int(sz),
			syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
		if err != nil {
			return fmt.Errorf("mmap kvm_run(%d): %w", i, err)
		}
		vc.run = kvmRunStruct{data: runBuf}
		b.vcpus = append(b.vcpus, vc)
	}

	m.irqLine = b.irqLine
	// secondary vCPUs: plain run loops on their own threads
	for _, vc := range b.vcpus[1:] {
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

func (b *kvmBackend) createGIC() error {
	cd := kvmCreateDeviceStruct{typ: kvmDevTypeArmVGICV3}
	if err := ioctl(b.vmFD, kvmCreateDevice, unsafe.Pointer(&cd)); err != nil {
		return fmt.Errorf("KVM_CREATE_DEVICE(GICv3): %w", err)
	}
	gic := uintptr(cd.fd)
	set := func(group, attr uint32, val uint64) error {
		da := kvmDeviceAttr{group: group, attr: uint64(attr), addr: uint64(uintptr(unsafe.Pointer(&val)))}
		return ioctl(gic, kvmSetDeviceAttr, unsafe.Pointer(&da))
	}
	if err := set(kvmDevArmVGICGrpNrIrqs, 0, 192); err != nil {
		return fmt.Errorf("GIC NR_IRQS: %w", err)
	}
	if err := set(kvmDevArmVGICGrpAddr, kvmVGICV3AddrTypeDist, gicdBase); err != nil {
		return fmt.Errorf("GIC dist addr: %w", err)
	}
	if err := set(kvmDevArmVGICGrpAddr, kvmVGICV3AddrTypeRedist, gicrBase); err != nil {
		return fmt.Errorf("GIC redist addr: %w", err)
	}
	if err := set(kvmDevArmVGICGrpCtrl, kvmDevArmVGICCtrlInit, 0); err != nil {
		return fmt.Errorf("GIC init: %w", err)
	}
	return nil
}

// irqLine asserts/deasserts a GIC interrupt line (INTID numbering).
func (b *kvmBackend) irqLine(irq int, level bool) {
	il := kvmIRQLevel{irq: uint32(irq)}
	if level {
		il.level = 1
	}
	_ = ioctl(b.vcpus[0].fd, kvmIRQLine, unsafe.Pointer(&il)) // best effort
}

func (vc *kvmVCPU) setReg(wordIndex uint64, val uint64) error {
	or := kvmOneReg{id: kvmRegArmCoreReg(wordIndex), addr: uint64(uintptr(unsafe.Pointer(&val)))}
	return ioctl(vc.fd, kvmSetOneReg, unsafe.Pointer(&or))
}

func (b *kvmBackend) bootLoop() error {
	m := b.m
	vc := b.vcpus[0]
	// arm64 Linux boot protocol: x0 = FDT phys, x1..x3 = 0, PC = kernel
	// entry, PSTATE = EL1h with DAIF masked, MMU off.
	if err := vc.setReg(0, fdtAddr); err != nil {
		return err
	}
	for i := uint64(1); i <= 3; i++ {
		if err := vc.setReg(i, 0); err != nil {
			return err
		}
	}
	if err := vc.setReg(32, m.entry); err != nil { // pc
		return err
	}
	if err := vc.setReg(33, pstateEL1hMask); err != nil { // pstate
		return err
	}

	fmt.Printf("booting guest (%d vCPU max; type 'exit' in guest shell or Ctrl-A X to quit)\n", m.vcpus)
	fmt.Println("------------------------------------------------")

	if m.consoleStdin {
		go m.uart.stdinPump(m.stdinDone)
		defer close(m.stdinDone)
	}
	return b.runVCPULoop(vc)
}

func (b *kvmBackend) runVCPULoop(vc *kvmVCPU) error {
	m := b.m
	for {
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, vc.fd, kvmRun, 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return fmt.Errorf("KVM_RUN: %w", errno)
		}
		switch vc.run.exitReason() {
		case kvmExitMMIO:
			phys := vc.run.mmioPhys()
			val := m.handleMMIO(vc.run.mmioIsWrite(), phys, vc.run.mmioData(), vc.run.mmioLen())
			if !vc.run.mmioIsWrite() {
				binary.LittleEndian.PutUint32(vc.run.mmioData(), val)
			}
		case kvmExitSystemEvent:
			switch vc.run.sysEventType() {
			case kvmSystemEventShutdown:
				m.stdoutFlush()
				fmt.Println("\n------------------------------------------------")
				fmt.Println("guest powered off (PSCI SYSTEM_OFF)")
				return nil
			case kvmSystemEventReset:
				fmt.Println("\nguest requested reset; exiting")
				return nil
			case kvmSystemEventCrash:
				return fmt.Errorf("guest crashed")
			}
		case kvmExitShutdown:
			fmt.Println("\nguest shutdown")
			return nil
		case kvmExitFailEntry:
			return fmt.Errorf("KVM_EXIT_FAIL_ENTRY (bad vcpu state?)")
		case kvmExitInternalError:
			return fmt.Errorf("KVM_EXIT_INTERNAL_ERROR suberror=%d", gutil.LE32(vc.run.data[32:]))
		default:
			// hypercalls, WFx, debug: nothing to do, re-enter
		}
	}
}

// platformBackend selects the hypervisor backend for this build target.
func platformBackend() backend { return kvmARM64Platform{} }
