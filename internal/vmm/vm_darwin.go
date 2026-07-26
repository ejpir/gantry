//go:build darwin

package vmm

import (
	"fmt"
	"gantry/internal/gutil"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// hvfBackend is the macOS Hypervisor.framework implementation.
//
// Differences vs the KVM backend:
//   - the vGIC is created via hv_gic_* (same GICD/GICR addresses; requires
//     macOS 13+; sailor calls this its hardware GIC mode)
//   - MMIO exits come as raw data-abort syndromes; we decode ESR ourselves
//     (ISV/SAS/WnR/SRT) instead of getting a pre-decoded kvm_run.mmio
//   - PSCI is NOT handled in-kernel: guest HVC calls exit to us and we
//     implement the PSCI 0.2 functions ourselves (including CPU_ON for SMP)
//
// SMP: vCPU 0 boots on the main run-loop thread; secondary vCPUs are
// created on demand when the guest calls PSCI CPU_ON (FDT advertises one
// cpu node per vCPU). Each vCPU runs on its own pinned OS thread — HVF
// vCPUs are thread-affine. Device-raised SPIs are global (hv_gic routes
// them); we kick every vCPU so the IRQ is applied promptly.
type hvfBackend struct {
	m     *Machine
	debug bool

	irqMu       sync.Mutex
	pendingIRQs []irqChange

	vcpuMu  sync.Mutex
	vcpus   []*hvfVCPU
	running map[int]bool
	// hvfMu serializes vCPU CREATION (hv_vcpu_create + initial register
	// setup). Concurrent HVF creation from multiple threads corrupts HVF
	// state. Post-creation per-vCPU calls happen on the owning thread and
	// hv_vcpu_run stays outside this lock.
	hvfMu sync.Mutex
	// secondaries: vCPU workers created and parked at VM start, keyed by
	// id; PSCI CPU_ON sends the entry/context (libkrun vstate.rs model:
	// every hv_vcpu_create finishes before any hv_vcpu_run begins, and
	// each vCPU is created on its own thread).
	secondaries map[int]chan psciStart
}

type psciStart struct {
	entry uint64
	ctx   uint64
}

// hvfVCPU is one virtual CPU with its own run loop.
type hvfVCPU struct {
	id    int
	vcpu  uint64
	exit  *hvVcpuExit
	b     *hvfBackend
	debug bool
	// inLoop is true while the vCPU is inside its run loop; IRQ kicks skip
	// parked vCPUs (hv_vcpus_exit on a never-run vCPU is pointless).
	inLoop atomic.Bool

	exits    map[uint64]uint64
	mmioHit  map[uint64]uint64
	seenMMIO map[uint64]bool
}

type irqChange struct {
	irq   int
	level bool
}

// queueIRQ records an IRQ line change and kicks ALL vCPUs out so a run
// loop applies it promptly. Safe to call from any goroutine.
func (b *hvfBackend) queueIRQ(irq int, level bool) {
	b.irqMu.Lock()
	b.pendingIRQs = append(b.pendingIRQs, irqChange{irq, level})
	b.irqMu.Unlock()
	b.vcpuMu.Lock()
	handles := make([]uint64, 0, len(b.vcpus))
	for _, vc := range b.vcpus {
		if vc.inLoop.Load() {
			handles = append(handles, vc.vcpu)
		}
	}
	b.vcpuMu.Unlock()
	if len(handles) > 0 {
		hvVcpusExit(&handles[0], uint32(len(handles))) // documented thread-safe
	}
}

// applyPendingIRQs runs on a run-loop thread right before hv_vcpu_run.
// SPI changes are global (hv_gic state), so it doesn't matter which vCPU
// applies them.
func (b *hvfBackend) applyPendingIRQs() {
	b.irqMu.Lock()
	qs := b.pendingIRQs
	b.pendingIRQs = nil
	b.irqMu.Unlock()
	for _, q := range qs {
		if b.debug {
			fmt.Printf("[gic] set_spi(%d, %v)\n", q.irq, q.level)
		}
		hvGicSetSpi(uint32(q.irq), q.level)
	}
}

func (vc *hvfVCPU) dumpState(why string) {
	pc, _ := vc.getReg(hvRegPC)
	x0, _ := vc.getReg(hvRegX0)
	cpsr, _ := vc.getReg(hvRegCPSR)
	lr, _ := vc.getReg(30)
	fmt.Printf("\n[debug] cpu%d %s\n[debug] PC=%#x X0=%#x LR=%#x CPSR=%#x\n[debug] exits=%v\n[debug] mmio=%v\n",
		vc.id, why, pc, x0, lr, cpsr, vc.exits, vc.mmioHit)
	// with nokaslr, kernel text: virt 0xffff800080000000 == phys 0x40000000
	if pc >= 0xffff800080000000 {
		phys := pc - 0xffff800080000000
		if phys >= ramBase && phys < ramBase+uint64(len(vc.b.m.ram)) {
			code := vc.b.m.ram[phys-ramBase : phys-ramBase+96]
			fmt.Printf("[debug] code@pc: % x\n", code)
		}
	}
}

// dumpFullState prints everything we know when hv_vcpu_run fails.
func (vc *hvfVCPU) dumpFullState() {
	fmt.Printf("\n[dump] cpu%d hv_vcpu_run failed; exit struct: reason=%d syn=%#x va=%#x pa=%#x\n",
		vc.id, vc.exit.reason, vc.exit.syndrome, vc.exit.virtualAddress, vc.exit.physicalAddress)
	for i := uint32(0); i < 31; i++ {
		v, err := vc.getReg(i)
		if err != nil {
			fmt.Printf("[dump] getReg(x%d) failed: %v (vCPU dead)\n", i, err)
			break
		}
		if i == 30 || v != 0 {
			fmt.Printf("[dump] x%-2d = %#x\n", i, v)
		}
	}
	pc, _ := vc.getReg(hvRegPC)
	cpsr, _ := vc.getReg(hvRegCPSR)
	fmt.Printf("[dump] pc=%#x cpsr=%#x\n", pc, cpsr)
}

// periodicKicker kicks all vCPUs out of hv_vcpu_run every 3s in debug mode
// (hv_vcpus_exit -> HV_EXIT_REASON_CANCELED), giving deterministic state
// dumps even when the guest spins without exiting.
func (b *hvfBackend) periodicKicker() {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for range t.C {
		b.vcpuMu.Lock()
		handles := make([]uint64, 0, len(b.vcpus))
		for _, vc := range b.vcpus {
			handles = append(handles, vc.vcpu)
		}
		b.vcpuMu.Unlock()
		if len(handles) > 0 {
			hvVcpusExit(&handles[0], uint32(len(handles)))
		}
	}
}

// siginfoDumper prints vCPU 0 state on SIGINFO (Ctrl-T). Reading registers
// from a second thread while the vCPU runs is technically racy, but fine
// for debugging.
func (b *hvfBackend) siginfoDumper() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINFO)
	for range ch {
		b.vcpuMu.Lock()
		var vc0 *hvfVCPU
		if len(b.vcpus) > 0 {
			vc0 = b.vcpus[0]
		}
		b.vcpuMu.Unlock()
		if vc0 == nil {
			continue
		}
		pc, _ := vc0.getReg(hvRegPC)
		x0, _ := vc0.getReg(hvRegX0)
		cpsr, _ := vc0.getReg(hvRegCPSR)
		fmt.Printf("\n[debug] cpu0 PC=%#x X0=%#x CPSR=%#x exits=%v\n", pc, x0, cpsr, vc0.exits)
		fmt.Printf("[debug] mmio addresses: %v\n", vc0.mmioHit)
	}
}

type hvfPlatform struct{}

func (hvfPlatform) run(m *Machine) (err error) {
	if m.arch != "arm64" {
		return fmt.Errorf("the macOS Hypervisor.framework backend boots arm64 guests only; use the Linux/KVM build for x86-64")
	}
	// Pin the run-loop goroutine to its OS thread: HVF vCPUs are
	// thread-affine. Go's scheduler would otherwise migrate this goroutine
	// between hv_vcpu_run calls, executing the vCPU on different host
	// threads and corrupting HVF state (all HVF calls then return garbage
	// and the vCPU dies — the bug we chased here).
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := loadHVF(); err != nil {
		return err
	}
	b := &hvfBackend{m: m, running: map[int]bool{}}

	cfg := hvVmConfigCreate()
	if ret := hvVmCreate(cfg); ret != hvSuccess {
		return fmt.Errorf("hv_vm_create: %s", hvReturnString(ret))
	}

	// guest RAM: same addresses as the KVM backend
	if ret := hvVmMap(unsafe.Pointer(&m.ram[0]), ramBase, uint64(len(m.ram)),
		hvMemoryRead|hvMemoryWrite|hvMemoryExec); ret != hvSuccess {
		return fmt.Errorf("hv_vm_map: %s", hvReturnString(ret))
	}

	// vGICv3 at our standard addresses
	gicCfg := hvGicConfigCreate()
	if ret := hvGicConfigSetDistributorBase(gicCfg, gicdBase); ret != hvSuccess {
		return fmt.Errorf("hv_gic_config_set_distributor_base: %s", hvReturnString(ret))
	}
	if ret := hvGicConfigSetRedistributorBase(gicCfg, gicrBase); ret != hvSuccess {
		return fmt.Errorf("hv_gic_config_set_redistributor_base: %s", hvReturnString(ret))
	}
	if ret := hvGicCreate(gicCfg); ret != hvSuccess {
		return fmt.Errorf("hv_gic_create: %s (needs macOS 13+)", hvReturnString(ret))
	}

	// vCPU 0 is created on (and owned by) this main run-loop thread.
	// Every secondary gets its own thread NOW: it creates its vCPU there
	// (hv_vcpu_create must run on the owning thread — creating a second
	// vCPU on this thread blocks forever) and parks until PSCI CPU_ON.
	// We wait for all creations to complete before vCPU 0 runs (creating
	// a vCPU while another vCPU is running crashes HVF).
	vc0, err := b.newVCPU(0)
	if err != nil {
		return err
	}
	b.secondaries = map[int]chan psciStart{}
	var wg sync.WaitGroup
	createErrs := make([]error, m.vcpus)
	for i := 1; i < m.vcpus; i++ {
		ch := make(chan psciStart, 1)
		b.secondaries[i] = ch
		wg.Add(1)
		go func(id int, start chan psciStart) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			vc, err := b.newVCPU(id)
			createErrs[id] = err
			wg.Done()
			if err != nil {
				return
			}
			s := <-start // parked until PSCI CPU_ON
			vc.setReg(hvRegX0, s.ctx)
			vc.setReg(hvRegPC, s.entry)
			vc.setReg(hvRegCPSR, pstateEL1hMask)
			if err := vc.runLoop(); err != nil && !isGuestHalt(err) {
				fmt.Fprintf(os.Stderr, "\n[cpu%d] run loop: %v\n", vc.id, err)
			}
			b.vcpuMu.Lock()
			delete(b.running, id)
			b.vcpuMu.Unlock()
		}(i, ch)
	}
	wg.Wait()
	for i := 1; i < m.vcpus; i++ {
		if createErrs[i] != nil {
			return fmt.Errorf("vcpu %d: %w", i, createErrs[i])
		}
	}
	// NOTE: do NOT mask the vtimer. Masked = HVF exits on every fire instead
	// of delivering the interrupt (for userspace-GIC users). Leaving it
	// unmasked lets HVF deliver the guest's timer interrupts directly.
	// (Bug found on first hardware run: masking starved the guest timer and
	// the kernel hung before console init.)

	// boot protocol: x0 = FDT, PC = kernel entry, CPSR = EL1h+DAIF
	vc0.setReg(hvRegX0, fdtAddr)
	vc0.setReg(hvRegPC, m.entry)
	vc0.setReg(hvRegCPSR, pstateEL1hMask)

	// All HVF calls are serialized on each vCPU's own run-loop thread:
	// device models (possibly called from other goroutines, e.g. the stdin
	// pump) only enqueue IRQ changes; a run loop applies them before
	// hv_vcpu_run. Calling HVF concurrently from multiple threads corrupts
	// its state (this caused hv_vcpu_run to return garbage codes).
	m.irqLine = func(irq int, level bool) { b.queueIRQ(irq, level) }

	fmt.Printf("booting guest under Hypervisor.framework (%d vCPU max)\n", m.vcpus)
	fmt.Println("------------------------------------------------")
	if m.consoleStdin {
		go m.uart.stdinPump(m.stdinDone)
		defer close(m.stdinDone)
	}
	if gutil.EnvOr("GANTRY_DEBUG", "MINIVM_DEBUG") != "" {
		b.debug = true
		vc0.debug = true
		go b.siginfoDumper()
		go b.periodicKicker()
		fmt.Println("[debug] GANTRY_DEBUG=1: exits logged, Ctrl-T dumps, 3s auto-dumps")
	}

	err = vc0.runLoop()
	if isGuestHalt(err) {
		return nil
	}
	return err
}

// newVCPU creates one vCPU (id becomes MPIDR Aff1, matching the FDT cpu
// nodes and the GIC redistributors) and registers it.
func (b *hvfBackend) newVCPU(id int) (*hvfVCPU, error) {
	// Serialize creation: concurrent hv_vcpu_create from several threads
	// corrupts HVF state.
	b.hvfMu.Lock()
	defer b.hvfMu.Unlock()
	vc := &hvfVCPU{
		id:       id,
		b:        b,
		debug:    b.debug,
		exits:    map[uint64]uint64{},
		mmioHit:  map[uint64]uint64{},
		seenMMIO: map[uint64]bool{},
	}
	var exitInfo *hvVcpuExit
	if ret := hvVcpuCreate(&vc.vcpu, &exitInfo, 0); ret != hvSuccess {
		return nil, fmt.Errorf("hv_vcpu_create: %s", hvReturnString(ret))
	}
	vc.exit = exitInfo
	// Aff1 = vcpu id so MPIDR matches the redistributor (libkrun does the same)
	mpidr := uint64(0x80000000) | uint64(id)<<8
	if ret := hvVcpuSetSysReg(vc.vcpu, hvSysRegMpidrEl1, mpidr); ret != hvSuccess {
		return nil, fmt.Errorf("hv_vcpu_set_sys_reg(MPIDR_EL1): %s", hvReturnString(ret))
	}
	// Give every vCPU a defined architectural state at creation (libkrun's
	// set_initial_state): a parked secondary with garbage CPSR/PC may make
	// HVF refuse to schedule the whole VM. CPU_ON overwrites these.
	if err := vc.setReg(hvRegCPSR, pstateEL1hMask); err != nil {
		return nil, fmt.Errorf("init cpsr: %w", err)
	}
	if err := vc.setReg(hvRegPC, vc.b.m.entry); err != nil {
		return nil, fmt.Errorf("init pc: %w", err)
	}
	if err := vc.setReg(hvRegX0, 0); err != nil {
		return nil, fmt.Errorf("init x0: %w", err)
	}
	b.vcpuMu.Lock()
	b.vcpus = append(b.vcpus, vc)
	b.vcpuMu.Unlock()
	return vc, nil
}

// startVCPU handles PSCI CPU_ON: release the parked secondary worker.
func (b *hvfBackend) startVCPU(id int, entry, ctx uint64) error {
	b.vcpuMu.Lock()
	defer b.vcpuMu.Unlock()
	ch, ok := b.secondaries[id]
	if !ok {
		return fmt.Errorf("target id %d out of range (max %d vcpus)", id, b.m.vcpus)
	}
	if b.running[id] {
		return fmt.Errorf("cpu%d already running", id)
	}
	b.running[id] = true
	fmt.Printf("[psci] CPU_ON cpu%d entry=%#x\n", id, entry)
	ch <- psciStart{entry: entry, ctx: ctx}
	return nil
}

func (vc *hvfVCPU) setReg(reg uint32, val uint64) error {
	if ret := hvVcpuSetReg(vc.vcpu, reg, val); ret != hvSuccess {
		return fmt.Errorf("hv_vcpu_set_reg(%d): %s", reg, hvReturnString(ret))
	}
	return nil
}

func (vc *hvfVCPU) getReg(reg uint32) (uint64, error) {
	var v uint64
	if ret := hvVcpuGetReg(vc.vcpu, reg, &v); ret != hvSuccess {
		return 0, fmt.Errorf("hv_vcpu_get_reg(%d): %s", reg, hvReturnString(ret))
	}
	return v, nil
}

func (vc *hvfVCPU) advancePC() {
	pc, err := vc.getReg(hvRegPC)
	if err == nil {
		vc.setReg(hvRegPC, pc+4)
	}
}

func (vc *hvfVCPU) runLoop() error {
	vc.inLoop.Store(true)
	defer vc.inLoop.Store(false)
	for {
		vc.b.applyPendingIRQs()
		if ret := hvVcpuRun(vc.vcpu); ret != hvSuccess {
			vc.dumpFullState()
			return fmt.Errorf("hv_vcpu_run: %s", hvReturnString(ret))
		}
		if vc.debug {
			vc.exits[uint64(vc.exit.reason)]++
			syn := vc.exit.syndrome
			ec := (syn >> 26) & 0x3f
			if vc.exit.reason != hvExitReasonException || (ec != ecWfi && ec != ecDataAbort && ec != ecDataAbortSame) {
				pc, _ := vc.getReg(hvRegPC)
				fmt.Printf("[debug] cpu%d exit reason=%d ec=%#x syn=%#x pc=%#x\n",
					vc.id, vc.exit.reason, ec, syn, pc)
			}
		}
		switch vc.exit.reason {
		case hvExitReasonVtimerActivated:
			// vtimer fired while masked: inject PPI 27 ourselves and unmask
			// so HVF can deliver it directly from now on (libkrun's flow).
			if gutil.EnvOr("GANTRY_NO_VTIMER_INJECT", "MINIVM_NO_VTIMER_INJECT") == "" {
				hvVcpuSetPendingInterrupt(vc.vcpu, hvInterruptTypeIRQ, true)
				hvVcpuSetVtimerMask(vc.vcpu, false)
			}
			continue
		case hvExitReasonCanceled:
			// someone kicked the vcpu out (hv_vcpus_exit): debug dump, IRQ
			// work to apply, or the periodic kicker. Never fatal.
			if vc.debug {
				vc.dumpState("canceled (kick)")
			}
			continue
		case hvExitReasonException:
			if err := vc.handleException(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected HVF exit reason %d", vc.exit.reason)
		}
	}
}

func (vc *hvfVCPU) handleException() error {
	syn := vc.exit.syndrome
	ec := (syn >> 26) & 0x3f
	switch ec {
	case 0x18: // MSR/MRS/system-instruction trap
		return vc.handleSysreg(syn)
	case ecWfi:
		// Guest idled. sailor sleeps the host thread here until the timer
		// or an IRQ ("vCPU WFI: sleeping until timer"); a short sleep keeps
		// us from burning a host core on idle guests.
		time.Sleep(time.Millisecond)
		return nil
	case ecHvc:
		return vc.handlePSCI()
	case ecDataAbort, ecDataAbortSame:
		return vc.handleDataAbort(syn)
	case ecBrk:
		return fmt.Errorf("guest hit BRK (debug breakpoint)")
	default:
		pc, _ := vc.getReg(hvRegPC)
		return fmt.Errorf("unhandled exception EC=%#x syndrome=%#x pc=%#x", ec, syn, pc)
	}
}

// handleDataAbort decodes ESR_EL2 for an MMIO access and routes it to the
// device model. Only the ISV=1 case (syndrome valid) is supported — Linux
// device drivers always produce decodable loads/stores here.
func (vc *hvfVCPU) handleDataAbort(syn uint64) error {
	if syn&(1<<24) == 0 { // ISV
		return fmt.Errorf("data abort with ISV=0 (syndrome=%#x)", syn)
	}
	sas := (syn >> 22) & 0x3
	length := uint32(1) << sas
	isWrite := (syn>>6)&1 != 0
	srt := uint32((syn >> 16) & 0x1f)
	phys := vc.exit.physicalAddress

	if vc.debug {
		vc.mmioHit[phys>>12]++ // count per 4K page
		if !vc.seenMMIO[phys>>12] {
			vc.seenMMIO[phys>>12] = true
			pc, _ := vc.getReg(hvRegPC)
			fmt.Printf("[debug] cpu%d mmio %s phys=%#x len=%d pc=%#x\n",
				vc.id, map[bool]string{true: "W", false: "R"}[isWrite], phys, length, pc)
		}
	}

	var data [8]byte
	if isWrite {
		var val uint64
		if srt < 31 {
			val, _ = vc.getReg(hvRegX0 + srt)
		}
		for i := uint32(0); i < length; i++ {
			data[i] = byte(val >> (8 * i))
		}
		vc.b.m.handleMMIO(true, phys, data[:], length)
	} else {
		val := uint64(vc.b.m.handleMMIO(false, phys, data[:], length))
		if srt < 31 {
			vc.setReg(hvRegX0+srt, val)
		}
	}
	// Device MMIO may have changed IRQ lines (e.g. UART FIFO drained by a
	// DR read): apply them NOW, before the guest re-enters — otherwise the
	// level-triggered line stays high, refires with nothing to handle, and
	// Linux disables the IRQ ("nobody cared").
	vc.b.applyPendingIRQs()
	vc.advancePC()
	return nil
}

// handleSysreg emulates trapped system-register accesses. HVF traps
// accesses it doesn't virtualize (debug registers like OSDLR_EL1, etc.).
// Policy: MSR writes are swallowed, MRS reads return 0, always logged
// (these are rare; any guest that genuinely depends on a value will show
// up in the log and we add a real model then).
func (vc *hvfVCPU) handleSysreg(syn uint64) error {
	dir := syn & 1 // 0 = MSR (write), 1 = MRS (read)
	rt := uint32((syn >> 5) & 0x1f)
	op0 := (syn >> 20) & 0x3
	op1 := (syn >> 14) & 0x7
	crn := (syn >> 10) & 0xf
	crm := (syn >> 1) & 0xf
	op2 := (syn >> 17) & 0x7
	fmt.Printf("[sysreg] %s S%d_%d_C%d_C%d_%d rt=x%d\n",
		map[bool]string{true: "MRS", false: "MSR"}[dir == 1],
		op0, op1, crn, crm, op2, rt)
	if dir == 1 && rt < 31 {
		vc.setReg(hvRegX0+rt, 0)
	}
	vc.advancePC() // PC points at the trapping instruction; step over it
	return nil
}

// handlePSCI implements the PSCI 0.2 functions the guest can call via HVC.
// On KVM this is done in-kernel; on HVF the VMM owns it.
func (vc *hvfVCPU) handlePSCI() error {
	fn, _ := vc.getReg(hvRegX0)
	const (
		psciVersion     = 0x84000000
		psciCPUOff      = 0x84000002
		psciCPUOn64     = 0xC4000003
		psciSystemOff   = 0x84000008
		psciSystemReset = 0x84000009
		psciFeatures    = 0x8400000A
		psciOK          = 0
		psciNotSupp     = ^uint64(0) // -1
		psciInvalid     = ^uint64(1) // -2
	)
	switch uint32(fn) {
	case psciVersion:
		vc.setReg(hvRegX0, 0x00010002) // v0.2
	case psciFeatures:
		vc.setReg(hvRegX0, psciOK) // all our functions need no flags
	case psciCPUOn64:
		mpidr, _ := vc.getReg(hvRegX0 + 1)
		entry, _ := vc.getReg(hvRegX0 + 2)
		ctx, _ := vc.getReg(hvRegX0 + 3)
		targetID := int((mpidr >> 8) & 0xff) // Aff1, matches FDT cpu@N
		if err := vc.b.startVCPU(targetID, entry, ctx); err != nil {
			fmt.Fprintf(os.Stderr, "[psci] CPU_ON cpu%d entry=%#x failed: %v\n", targetID, entry, err)
			vc.setReg(hvRegX0, psciInvalid)
		} else {
			vc.setReg(hvRegX0, psciOK)
		}
	case psciCPUOff:
		if vc.id != 0 {
			// secondary going down: end this vCPU's run loop quietly
			return errGuestHalt
		}
		fmt.Println("\nguest CPU_OFF")
		return errGuestHalt
	case psciSystemReset:
		fmt.Println("\nguest requested reset; exiting")
		return errGuestHalt
	case psciSystemOff:
		vc.b.m.stdoutFlush()
		fmt.Println("\n------------------------------------------------")
		fmt.Println("guest powered off (PSCI SYSTEM_OFF)")
		return errGuestHalt
	default:
		vc.setReg(hvRegX0, psciNotSupp)
	}
	// NOTE: do NOT advance PC here. For HVC/SVC exceptions the saved PC
	// already points at the instruction AFTER the trap (unlike data-abort
	// MMIO exits, where it points at the faulting instruction). Advancing
	// here once skipped the kernel's post-hvc reload and caused a NULL
	// store in __arm_smccc_hvc (psci_probe panic).
	return nil
}

var errGuestHalt = fmt.Errorf("guest halted")

func isGuestHalt(err error) bool { return err == errGuestHalt }

// platformBackend selects the hypervisor backend for this build target.
func platformBackend() backend { return hvfPlatform{} }
