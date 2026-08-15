//go:build darwin

package vmm

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/ejpir/gantry/internal/gutil"
)

// hvfBackend is the macOS Hypervisor.framework implementation.
//
// Differences vs the KVM backend:
//   - the vGIC is created via hv_gic_* (same GICD/GICR addresses; requires
//     macOS 13+; the reference VMM calls this its hardware GIC mode)
//   - MMIO exits come as raw data-abort syndromes; we decode ESR ourselves
//     (ISV/SAS/WnR/SRT) instead of getting a pre-decoded kvm_run.mmio
//   - PSCI is NOT handled in-kernel: guest HVC calls exit to us and we
//     implement the PSCI 0.2 functions ourselves (including CPU_ON for SMP)
//
// SMP: vCPU 0 boots on the main run-loop thread; secondary vCPUs are created
// at VM startup on dedicated pinned threads, then parked until the guest calls
// PSCI CPU_ON (FDT advertises one node per vCPU). HVF vCPUs are thread-affine.
// Device-raised SPIs are global (hv_gic routes them); we kick every vCPU so
// the IRQ is applied promptly.
type hvfBackend struct {
	m         *Machine
	debug     bool
	lifecycle *nativeBackendLifecycle
	ramSize   uint64

	vmCreated bool
	mapped    bool

	irqs     serializedIRQDelivery
	shutdown *nativeThreadTeardown

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
	// wake releases a vCPU parked on WFI. hv_vcpus_exit only breaks
	// hv_vcpu_run, so an idling vCPU — which is NOT inside the hypervisor —
	// needs its own wakeup path or it sits out the whole idle bound while
	// the interrupt it is waiting for is already queued. Buffered by one: a
	// token left by an IRQ raised while the guest was running costs one
	// spurious wakeup, which is the safe direction to err in.
	wake chan struct{}
	// run accounting (profile-only, reported on the boot timeline): what the
	// vCPU actually did, since neither the guest's clock nor the host's wall
	// time alone can distinguish guest execution from trap storms from
	// host-side idling. The immutable flag keeps atomics off the basic timing
	// and normal run paths.
	bootAccounting bool
	statExits      atomic.Uint64
	statWFI        atomic.Uint64
	statMMIO       atomic.Uint64
	statSysreg     atomic.Uint64
	statOther      atomic.Uint64
	idleWaits      atomic.Uint64
	idleBlocked    atomic.Int64
	idleCapped     atomic.Uint64
	// profiled counts boot PC samples taken. Owned by the run-loop thread.
	profiled int

	debugMu  sync.Mutex
	exits    map[uint64]uint64
	mmioHit  map[uint64]uint64
	seenMMIO map[uint64]bool
}

// deliverIRQ injects the VM-global GIC line change on the calling device thread.
// hv_gic_set_spi is itself the guest wakeup for an SPI; deferring it until a
// vCPU exits loses interrupts when hv_vcpus_exit lands between run calls.
func (b *hvfBackend) deliverIRQ(irq int, level bool) {
	if b.lifecycle.isStopping() {
		return
	}
	err := b.irqs.inject(irqChange{irq: irq, level: level}, func(irq int, level bool) error {
		if b.debug {
			fmt.Printf("[gic] set_spi(%d, %v)\n", irq, level)
		}
		if ret := hvGicSetSpi(uint32(irq), level); ret != hvSuccess {
			return fmt.Errorf("hv_gic_set_spi: %s", hvReturnString(ret))
		}
		return nil
	})
	if err != nil {
		b.lifecycle.recordError(err)
		b.lifecycle.stop()
		if kickErr := b.kickVCPUs(); kickErr != nil {
			b.lifecycle.recordError(kickErr)
		}
		return
	}
	b.wakeIdleVCPUs()
}

// wakeIdleVCPUs releases run-loop threads parked after a trapped WFI. vCPUs
// currently in hv_vcpu_run are woken by the injected GIC interrupt itself.
func (b *hvfBackend) wakeIdleVCPUs() {
	b.vcpuMu.Lock()
	for _, vc := range b.vcpus {
		vc.signalWake()
	}
	b.vcpuMu.Unlock()
}

func (b *hvfBackend) kickVCPUs() error {
	b.vcpuMu.Lock()
	handles := make([]uint64, 0, len(b.vcpus))
	for _, vc := range b.vcpus {
		// Both halves of "kick": hv_vcpus_exit for whoever is inside the
		// hypervisor, wake for whoever is parked on WFI outside it.
		vc.signalWake()
		if vc.inLoop.Load() {
			handles = append(handles, vc.vcpu)
		}
	}
	if len(handles) == 0 {
		b.vcpuMu.Unlock()
		return nil
	}
	ret := hvVcpusExit(&handles[0], uint32(len(handles)))
	b.vcpuMu.Unlock()
	if ret != hvSuccess {
		return fmt.Errorf("hv_vcpus_exit: %s", hvReturnString(ret))
	}
	return nil
}

func (b *hvfBackend) stopVCPUs() error {
	err := b.kickVCPUs()
	if b.shutdown != nil {
		b.shutdown.releaseOwners()
	}
	return err
}

func (b *hvfBackend) releaseNative() error {
	var errs []error
	if b.mapped {
		if ret := hvVmUnmap(ramBase, b.ramSize); ret != hvSuccess {
			errs = append(errs, fmt.Errorf("hv_vm_unmap: %s", hvReturnString(ret)))
		}
		b.mapped = false
	}
	if b.vmCreated {
		// Hypervisor.framework owns the GIC instance as part of the VM; there
		// is no separate GIC destroy API.
		if ret := hvVmDestroy(); ret != hvSuccess {
			errs = append(errs, fmt.Errorf("hv_vm_destroy: %s", hvReturnString(ret)))
		}
		b.vmCreated = false
	}
	return errors.Join(errs...)
}

func (b *hvfBackend) Close() error {
	return b.lifecycle.close(b.stopVCPUs, b.releaseNative)
}

func (b *hvfBackend) unregisterVCPU(vc *hvfVCPU) {
	b.vcpuMu.Lock()
	for i, candidate := range b.vcpus {
		if candidate == vc {
			copy(b.vcpus[i:], b.vcpus[i+1:])
			b.vcpus[len(b.vcpus)-1] = nil
			b.vcpus = b.vcpus[:len(b.vcpus)-1]
			break
		}
	}
	delete(b.running, vc.id)
	delete(b.secondaries, vc.id)
	b.vcpuMu.Unlock()
}

// destroyVCPU must run on the same locked OS thread that created vc.
func (b *hvfBackend) destroyVCPU(vc *hvfVCPU) {
	b.unregisterVCPU(vc)
	if ret := hvVcpuDestroy(vc.vcpu); ret != hvSuccess {
		b.lifecycle.recordError(fmt.Errorf("destroy HVF vCPU %d: %s", vc.id, hvReturnString(ret)))
	}
}

func (b *hvfBackend) finishVCPU(vc *hvfVCPU) {
	if b.shutdown != nil {
		b.shutdown.finishOwner(func() {
			if vc != nil {
				b.destroyVCPU(vc)
			}
		})
		return
	}
	if vc != nil {
		b.destroyVCPU(vc)
	}
}

func (vc *hvfVCPU) dumpState(why string) {
	pc, _ := vc.getReg(hvRegPC)
	x0, _ := vc.getReg(hvRegX0)
	cpsr, _ := vc.getReg(hvRegCPSR)
	lr, _ := vc.getReg(hvRegLR)
	vc.debugMu.Lock()
	defer vc.debugMu.Unlock()
	fmt.Printf("\n[debug] cpu%d %s\n[debug] PC=%#x X0=%#x LR=%#x CPSR=%#x\n[debug] exits=%v\n[debug] mmio=%v\n",
		vc.id, why, pc, x0, lr, cpsr, vc.exits, vc.mmioHit)
	// with nokaslr, kernel text: virt kernelTextVA == phys 0x40000000
	if pc >= kernelTextVA {
		phys := pc - kernelTextVA
		if phys >= ramBase && phys < ramBase+uint64(len(vc.b.m.ram)) {
			offset := phys - ramBase
			code := vc.b.m.ram[offset:min(offset+96, uint64(len(vc.b.m.ram)))]
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

// Boot profiling: when GANTRY_BOOT_PROFILE=1 accompanies the timeline,
// interrupt the guest every bootProfileInterval and record its PC. Sampling
// is intentionally separate from GANTRY_BOOT_TIMING because forcing exits is
// observably perturbing, especially as the vCPU count grows.
const (
	bootProfileInterval   = 5 * time.Millisecond
	maxBootProfileSamples = 64
	// kernelTextVA is where the arm64 kernel image is mapped with nokaslr;
	// PC minus this is an offset resolvable against the kernel's symbols.
	kernelTextVA = 0xffff800080000000
)

// bootProfiler drives the sampling. It retires at the last boot milestone:
// the question it answers is only about boot, and an idle guest should not
// be woken for diagnostics.
func (b *hvfBackend) bootProfiler(stop <-chan struct{}) error {
	if !b.m.bootTiming.profiling() {
		return nil
	}
	ticker := time.NewTicker(bootProfileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return nil
		case <-ticker.C:
			if b.m.bootTiming.bootComplete() {
				return nil
			}
			if err := b.kickVCPUs(); err != nil && !b.lifecycle.isStopping() {
				return err
			}
		}
	}
}

// sampleGuestPC runs on the owning thread after a cancellation (Apple requires
// vCPU register access there), so the PC is the guest's own.
func (vc *hvfVCPU) sampleGuestPC() {
	timeline := vc.b.m.bootTiming
	if !timeline.profiling() || vc.profiled >= maxBootProfileSamples || timeline.bootComplete() {
		return
	}
	pc, err := vc.getReg(hvRegPC)
	if err != nil {
		return
	}
	vc.profiled++
	// LR names the caller, which is the part a PC alone cannot give: a hot
	// leaf says what the guest is doing, not which loop is doing it. x0/x1
	// carry that call's arguments.
	lr, _ := vc.getReg(hvRegLR)
	x0, _ := vc.getReg(hvRegX0)
	x1, _ := vc.getReg(hvRegX0 + 1)
	detail := fmt.Sprintf(" lr %s x0 %#x x1 %#x", kernelSymbolish(lr), x0, x1)
	timeline.sample(vc.id, pc, kernelTextVA, detail+vc.b.m.codeAtPC(pc))
}

// kernelSymbolish renders an address as a kernel-text offset when it is one,
// so a caller can be resolved against the image without a symbol table.
func kernelSymbolish(addr uint64) string {
	if addr < kernelTextVA {
		return fmt.Sprintf("%#x", addr)
	}
	return fmt.Sprintf("text+%#x", addr-kernelTextVA)
}

// codeAtPC renders the instruction words the guest is executing, so a sample
// is readable without the guest kernel's symbol table: a loop of cache or TLB
// maintenance ops looks nothing like a loop of ordinary loads and stores.
//
// With nokaslr the kernel image is mapped at kernelTextVA and loaded at the
// entry address, so a text offset resolves against the LOAD address — not the
// start of RAM, which is where the FDT lives. A PC outside the image (guest
// userspace, the linear map, an early physical-address stretch) resolves to
// nothing and simply prints without code.
func (m *Machine) codeAtPC(pc uint64) string {
	const words = 8
	if pc < kernelTextVA || m.entry < ramBase {
		return ""
	}
	phys := m.entry + (pc - kernelTextVA)
	if phys < ramBase || phys+words*4 > ramBase+uint64(len(m.ram)) {
		return ""
	}
	code := m.ram[phys-ramBase:]
	out := fmt.Sprintf(" pa %#x code:", phys)
	for i := range words {
		out += fmt.Sprintf(" %08x", gutil.LE32(code[i*4:]))
	}
	return out
}

// periodicKicker kicks all vCPUs out of hv_vcpu_run every 3s in debug mode
// (hv_vcpus_exit -> HV_EXIT_REASON_CANCELED), giving deterministic state
// dumps even when the guest spins without exiting.
func (b *hvfBackend) periodicKicker(stop <-chan struct{}) error {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return nil
		case <-t.C:
			if err := b.kickVCPUs(); err != nil && !b.lifecycle.isStopping() {
				return err
			}
		}
	}
}

// siginfoDumper prints the userspace exit counters on SIGINFO (Ctrl-T).
// Hypervisor registers are intentionally not read here: Apple requires vCPU
// operations to stay on the owning thread, including during teardown.
func (b *hvfBackend) siginfoDumper(stop <-chan struct{}) error {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINFO)
	defer signal.Stop(ch)
	for {
		select {
		case <-stop:
			return nil
		case <-ch:
			b.vcpuMu.Lock()
			var vc0 *hvfVCPU
			for _, vc := range b.vcpus {
				if vc.id == 0 {
					vc0 = vc
					break
				}
			}
			b.vcpuMu.Unlock()
			if vc0 == nil {
				continue
			}
			vc0.debugMu.Lock()
			fmt.Printf("\n[debug] cpu0 exits=%v\n", vc0.exits)
			fmt.Printf("[debug] mmio addresses: %v\n", vc0.mmioHit)
			vc0.debugMu.Unlock()
		}
	}
}

type hvfPlatform struct{}

func (hvfPlatform) run(m *Machine) (resultErr error) {
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
	debug := os.Getenv("GANTRY_DEBUG") != ""
	workerCount := m.vcpus
	if debug {
		workerCount += 2 // SIGINFO dumper and periodic kicker
	}
	if m.bootTiming.profiling() {
		workerCount++ // perturbing boot PC sampler
	}
	b := &hvfBackend{
		m:           m,
		debug:       debug,
		lifecycle:   newNativeBackendLifecycle(workerCount),
		ramSize:     uint64(len(m.ram)),
		running:     map[int]bool{},
		secondaries: map[int]chan psciStart{},
	}
	m.bootTiming.setRunStats(b.runStats)
	var vc0 *hvfVCPU
	mainClaimed := false
	defer func() {
		// Apple's hv_vcpu_destroy must run on the vCPU's owning thread. This
		// function remains pinned until vc0 is gone. Close runs separately so
		// its barrier can wait for this thread to leave the run loop; it then
		// releases every owner to destroy its vCPU before VM teardown.
		var closeErr error
		if b.shutdown != nil {
			closed := make(chan error, 1)
			go func() { closed <- b.Close() }()
			b.finishVCPU(vc0)
			b.lifecycle.workerDone()
			closeErr = <-closed
		} else {
			b.lifecycle.stop()
			if vc0 != nil {
				b.destroyVCPU(vc0)
			}
			if mainClaimed {
				b.lifecycle.workerDone()
			}
			closeErr = b.Close()
		}
		if closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()

	cfg := hvVmConfigCreate()
	if cfg == 0 {
		return fmt.Errorf("hv_vm_config_create returned nil")
	}
	if ret := hvVmCreate(cfg); ret != hvSuccess {
		osRelease(cfg)
		return fmt.Errorf("hv_vm_create: %s", hvReturnString(ret))
	}
	osRelease(cfg)
	b.vmCreated = true

	// guest RAM: same addresses as the KVM backend
	if ret := hvVmMap(unsafe.Pointer(&m.ram[0]), ramBase, uint64(len(m.ram)),
		hvMemoryRead|hvMemoryWrite|hvMemoryExec); ret != hvSuccess {
		return fmt.Errorf("hv_vm_map: %s", hvReturnString(ret))
	}
	b.mapped = true

	// vGICv3 at our standard addresses
	gicCfg := hvGicConfigCreate()
	if gicCfg == 0 {
		return fmt.Errorf("hv_gic_config_create returned nil")
	}
	if ret := hvGicConfigSetDistributorBase(gicCfg, gicdBase); ret != hvSuccess {
		osRelease(gicCfg)
		return fmt.Errorf("hv_gic_config_set_distributor_base: %s", hvReturnString(ret))
	}
	if ret := hvGicConfigSetRedistributorBase(gicCfg, gicrBase); ret != hvSuccess {
		osRelease(gicCfg)
		return fmt.Errorf("hv_gic_config_set_redistributor_base: %s", hvReturnString(ret))
	}
	if ret := hvGicCreate(gicCfg); ret != hvSuccess {
		osRelease(gicCfg)
		return fmt.Errorf("hv_gic_create: %s (needs macOS 13+)", hvReturnString(ret))
	}
	osRelease(gicCfg)

	// vCPU 0 is created on (and owned by) this main run-loop thread.
	// Every secondary gets its own thread NOW: it creates its vCPU there
	// (hv_vcpu_create must run on the owning thread — creating a second
	// vCPU on this thread blocks forever) and parks until PSCI CPU_ON.
	// We wait for all creations to complete before vCPU 0 runs (creating
	// a vCPU while another vCPU is running crashes HVF).
	var err error
	vc0, err = b.newVCPU(0)
	if err != nil {
		return err
	}
	if !b.lifecycle.claimWorker() {
		return errMachineClosed
	}
	mainClaimed = true
	b.shutdown = newNativeThreadTeardown(m.vcpus)
	type createResult struct {
		id  int
		err error
	}
	created := make(chan createResult, max(0, m.vcpus-1))
	for i := 1; i < m.vcpus; i++ {
		ch := make(chan psciStart, 1)
		b.secondaries[i] = ch
		go func(id int, start chan psciStart) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			b.lifecycle.runWorker(func(stop <-chan struct{}) {
				vc, createErr := b.newVCPU(id)
				created <- createResult{id: id, err: createErr}
				if createErr != nil {
					b.finishVCPU(nil)
					return
				}
				defer b.finishVCPU(vc)
				for {
					var s psciStart
					select {
					case <-stop:
						return
					case s = <-start:
					}
					if err := vc.setReg(hvRegX0, s.ctx); err != nil {
						b.failVCPU(id, err)
						return
					}
					if err := vc.setReg(hvRegPC, s.entry); err != nil {
						b.failVCPU(id, err)
						return
					}
					if err := vc.setReg(hvRegCPSR, pstateEL1hMask); err != nil {
						b.failVCPU(id, err)
						return
					}
					runErr := vc.runLoop()
					b.vcpuMu.Lock()
					delete(b.running, id)
					b.vcpuMu.Unlock()
					if isGuestHalt(runErr) {
						continue
					}
					if runErr != nil {
						b.failVCPU(id, runErr)
					}
					return
				}
			})
		}(i, ch)
	}
	var createErr error
	for range m.vcpus - 1 {
		result := <-created
		if result.err != nil && createErr == nil {
			createErr = fmt.Errorf("vcpu %d: %w", result.id, result.err)
		}
	}
	if createErr != nil {
		return createErr
	}
	// NOTE: do NOT mask the vtimer. Masked = HVF exits on every fire instead
	// of delivering the interrupt (for userspace-GIC users). Leaving it
	// unmasked lets HVF deliver the guest's timer interrupts directly.
	// (Bug found on first hardware run: masking starved the guest timer and
	// the kernel hung before console init.)

	// All vCPU owner threads are now live and accounted for. Publishing the
	// backend lets a concurrent Machine.Close stop them and wait for their
	// thread-affine destruction.
	if err := m.adoptBackend(b); err != nil {
		return err
	}

	// boot protocol: x0 = FDT, PC = kernel entry, CPSR = EL1h+DAIF
	if err := vc0.setReg(hvRegX0, fdtAddr); err != nil {
		return err
	}
	if err := vc0.setReg(hvRegPC, m.entry); err != nil {
		return err
	}
	if err := vc0.setReg(hvRegCPSR, pstateEL1hMask); err != nil {
		return err
	}

	// vCPU-specific HVF calls stay on each vCPU's owning run-loop thread.
	// VM-global GIC injection is safe from device threads and is serialized by
	// deliverIRQ so concurrent devices cannot overlap framework calls or reorder
	// interrupt-line transitions.
	m.interrupts.set(func(irq int, level bool) { b.deliverIRQ(irq, level) })

	fmt.Printf("booting guest under Hypervisor.framework (%d vCPU max)\n", m.vcpus)
	fmt.Println("------------------------------------------------")
	if m.consoleStdin {
		go m.uart.stdinPump(m.stdinDone)
		defer close(m.stdinDone)
	}
	if m.bootTiming.profiling() {
		go b.lifecycle.runWorker(func(stop <-chan struct{}) {
			b.lifecycle.recordError(b.bootProfiler(stop))
		})
	}
	if debug {
		go b.lifecycle.runWorker(func(stop <-chan struct{}) {
			b.lifecycle.recordError(b.siginfoDumper(stop))
		})
		go b.lifecycle.runWorker(func(stop <-chan struct{}) {
			b.lifecycle.recordError(b.periodicKicker(stop))
		})
		fmt.Println("[debug] GANTRY_DEBUG=1: exits logged, Ctrl-T dumps, 3s auto-dumps")
	}

	err = vc0.runLoop()
	if isGuestHalt(err) {
		return nil
	}
	return err
}

func (b *hvfBackend) failVCPU(id int, err error) {
	if err == nil || isGuestHalt(err) || b.lifecycle.isStopping() {
		return
	}
	workerErr := fmt.Errorf("HVF vCPU %d: %w", id, err)
	b.lifecycle.recordError(workerErr)
	fmt.Fprintf(os.Stderr, "\n[cpu%d] run loop: %v\n", id, err)
	b.lifecycle.stop()
	if kickErr := b.kickVCPUs(); kickErr != nil {
		b.lifecycle.recordError(kickErr)
	}
}

// newVCPU creates one vCPU (id becomes MPIDR Aff1, matching the FDT CPU
// nodes and the GIC redistributors) and registers it.
func (b *hvfBackend) newVCPU(id int) (_ *hvfVCPU, resultErr error) {
	// Serialize creation: concurrent hv_vcpu_create from several threads
	// corrupts HVF state.
	b.hvfMu.Lock()
	defer b.hvfMu.Unlock()
	vc := &hvfVCPU{
		id:             id,
		b:              b,
		debug:          b.debug,
		bootAccounting: b.m.bootTiming.profiling(),
		wake:           make(chan struct{}, 1),
		exits:          map[uint64]uint64{},
		mmioHit:        map[uint64]uint64{},
		seenMMIO:       map[uint64]bool{},
	}
	var exitInfo *hvVcpuExit
	if ret := hvVcpuCreate(&vc.vcpu, &exitInfo, 0); ret != hvSuccess {
		return nil, fmt.Errorf("hv_vcpu_create: %s", hvReturnString(ret))
	}
	created := true
	defer func() {
		if resultErr == nil || !created {
			return
		}
		if ret := hvVcpuDestroy(vc.vcpu); ret != hvSuccess {
			resultErr = errors.Join(resultErr,
				fmt.Errorf("destroy partially initialized HVF vCPU %d: %s", id, hvReturnString(ret)))
		}
	}()
	vc.exit = exitInfo
	// Aff1 = vcpu id so MPIDR matches the redistributor (libkrun does the same)
	mpidr := uint64(0x80000000) | uint64(guestVCPUMPIDR(id))
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
	created = false
	return vc, nil
}

// startVCPU handles PSCI CPU_ON: release the parked secondary worker.
func (b *hvfBackend) startVCPU(id int, entry, ctx uint64) error {
	b.vcpuMu.Lock()
	defer b.vcpuMu.Unlock()
	if b.lifecycle.isStopping() {
		return errMachineClosed
	}
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
		_ = vc.setReg(hvRegPC, pc+4)
	}
}

// Per-exit trace budget. The opening exits are always shown (they are the
// firmware handshake), and after that only stretches worth explaining — with
// earlycon the guest emits hundreds of short UART exits, and a
// first-N-only trace would spend its whole budget on them before reaching
// the long runs that motivated the trace.
const (
	maxTracedExits    = 48
	alwaysTracedExits = 12
	longExitThreshold = 2 * time.Millisecond
)

func (vc *hvfVCPU) runLoop() error {
	vc.inLoop.Store(true)
	defer vc.inLoop.Store(false)
	firstRun := true
	traced, printed := 0, 0
	for {
		if vc.b.lifecycle.isStopping() {
			return nil
		}
		if firstRun {
			if vc.id == 0 {
				// Capture immediately before the boot vCPU's first hv_vcpu_run.
				vc.b.m.bootTiming.start("vCPU entered HVF")
			}
			firstRun = false
		}
		timing := vc.b.m.bootTiming.profiling() && printed < maxTracedExits && !vc.b.m.bootTiming.bootComplete()
		var entered time.Time
		if timing {
			entered = time.Now()
		}
		if ret := hvVcpuRun(vc.vcpu); ret != hvSuccess {
			if vc.b.lifecycle.isStopping() {
				return nil
			}
			vc.dumpFullState()
			return fmt.Errorf("hv_vcpu_run: %s", hvReturnString(ret))
		}
		if vc.bootAccounting {
			vc.statExits.Add(1)
		}
		if timing {
			traced++
			if ran := time.Since(entered); traced <= alwaysTracedExits || ran >= longExitThreshold {
				printed++
				ec := (vc.exit.syndrome >> 26) & 0x3f
				vc.b.m.bootTiming.traceExit(traced, ran,
					vc.exit.reason, ec, vc.traceDetail(ec))
			}
		}
		if vc.debug {
			vc.debugMu.Lock()
			vc.exits[uint64(vc.exit.reason)]++
			vc.debugMu.Unlock()
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
			if vc.bootAccounting {
				vc.statOther.Add(1)
			}
			// vtimer fired while masked: inject PPI 27 ourselves and unmask
			// so HVF can deliver it directly from now on (libkrun's flow).
			if os.Getenv("GANTRY_NO_VTIMER_INJECT") == "" {
				hvVcpuSetPendingInterrupt(vc.vcpu, hvInterruptTypeIRQ, true)
				hvVcpuSetVtimerMask(vc.vcpu, false)
			}
			continue
		case hvExitReasonCanceled:
			if vc.bootAccounting {
				vc.statOther.Add(1)
			}
			if vc.b.lifecycle.isStopping() {
				return nil
			}
			vc.sampleGuestPC()
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

// traceDetail names what an early exit was for, so the boot trace says which
// guest phase brackets a long run rather than just its exception class. HVC
// carries the SMCCC/PSCI function id in x0; a data abort carries the address
// the guest touched. Only traced exits pay the register read.
func (vc *hvfVCPU) traceDetail(ec uint64) string {
	switch ec {
	case ecHvc:
		fn, err := vc.getReg(hvRegX0)
		if err != nil {
			return ""
		}
		return fmt.Sprintf(", smccc fn %#x", fn)
	case ecDataAbort, ecDataAbortSame:
		return fmt.Sprintf(", pa %#x", vc.exit.physicalAddress)
	default:
		return ""
	}
}

// idleBound is how long a WFI parks with nothing to wake it. It is a
// backstop, not the wakeup mechanism: device interrupts release the vCPU
// immediately through wake, so the bound only paces guests waiting on the
// vtimer, which HVF cannot deliver while we are outside hv_vcpu_run.
const idleBound = time.Millisecond

// idle parks the vCPU until something wants it back. Blocking here (rather
// than spinning in hv_vcpu_run) keeps an idle guest off a host core.
func (vc *hvfVCPU) idle() {
	timer := time.NewTimer(idleBound)
	defer timer.Stop()
	var start time.Time
	if vc.bootAccounting {
		start = time.Now()
	}
	select {
	case <-vc.wake:
	case <-timer.C:
		if vc.bootAccounting {
			vc.idleCapped.Add(1)
		}
	}
	if vc.bootAccounting {
		vc.idleWaits.Add(1)
		vc.idleBlocked.Add(int64(time.Since(start)))
	}
}

// signalWake releases a vCPU parked in idle. Never blocks: a full buffer
// already means "go look again".
func (vc *hvfVCPU) signalWake() {
	select {
	case vc.wake <- struct{}{}:
	default:
	}
}

// runStats totals what the vCPUs did, for the boot timeline. Cheap enough to
// stay unconditional: a handful of atomic loads per milestone line.
func (b *hvfBackend) runStats() runStats {
	b.vcpuMu.Lock()
	defer b.vcpuMu.Unlock()
	var s runStats
	for _, vc := range b.vcpus {
		s.Exits += vc.statExits.Load()
		s.WFI += vc.statWFI.Load()
		s.MMIO += vc.statMMIO.Load()
		s.Sysreg += vc.statSysreg.Load()
		s.Other += vc.statOther.Load()
		s.IdleWaits += vc.idleWaits.Load()
		s.IdleCapped += vc.idleCapped.Load()
		s.IdleBlocked += time.Duration(vc.idleBlocked.Load())
	}
	return s
}

func (vc *hvfVCPU) handleException() error {
	syn := vc.exit.syndrome
	ec := (syn >> 26) & 0x3f
	switch ec {
	case 0x18: // MSR/MRS/system-instruction trap
		if vc.bootAccounting {
			vc.statSysreg.Add(1)
		}
		return vc.handleSysreg(syn)
	case ecWfi:
		if vc.bootAccounting {
			vc.statWFI.Add(1)
		}
		vc.idle()
		return nil
	case ecHvc:
		if vc.bootAccounting {
			vc.statOther.Add(1)
		}
		return vc.handlePSCI()
	case ecDataAbort, ecDataAbortSame:
		if vc.bootAccounting {
			vc.statMMIO.Add(1)
		}
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
		vc.debugMu.Lock()
		vc.mmioHit[phys>>12]++ // count per 4K page
		if !vc.seenMMIO[phys>>12] {
			vc.seenMMIO[phys>>12] = true
			pc, _ := vc.getReg(hvRegPC)
			fmt.Printf("[debug] cpu%d mmio %s phys=%#x len=%d pc=%#x\n",
				vc.id, map[bool]string{true: "W", false: "R"}[isWrite], phys, length, pc)
		}
		vc.debugMu.Unlock()
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
			_ = vc.setReg(hvRegX0+srt, val)
		}
	}
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
		_ = vc.setReg(hvRegX0+rt, 0)
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
		_ = vc.setReg(hvRegX0, 0x00010002) // v0.2
	case psciFeatures:
		_ = vc.setReg(hvRegX0, psciOK) // all our functions need no flags
	case psciCPUOn64:
		mpidr, _ := vc.getReg(hvRegX0 + 1)
		entry, _ := vc.getReg(hvRegX0 + 2)
		ctx, _ := vc.getReg(hvRegX0 + 3)
		targetID := guestVCPUIndex(mpidr)
		if err := vc.b.startVCPU(targetID, entry, ctx); err != nil {
			fmt.Fprintf(os.Stderr, "[psci] CPU_ON cpu%d entry=%#x failed: %v\n", targetID, entry, err)
			_ = vc.setReg(hvRegX0, psciInvalid)
		} else {
			_ = vc.setReg(hvRegX0, psciOK)
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
		_ = vc.setReg(hvRegX0, psciNotSupp)
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
