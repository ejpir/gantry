//go:build windows

package vmm

// Windows Hypervisor Platform (WHPX) backend for x86-64 guests — the same
// hypervisor API the reference Windows VMM uses (WHvCreatePartition /
// WHvRunVirtualProcessor; verified in the release binary).
//
// Unlike KVM there is no in-kernel irqchip/PIT: the LAPIC is emulated by
// WHPX, while the IO-APIC (ioapic.go), i8254 PIT (pit.go), i8259 PIC
// (pic.go), 16550 UART (uart16550.go) and CMOS RTC (cmos.go) are userspace.
// MMIO exits carry instruction bytes (no operand value), so writes are
// decoded with x86emul.go. WHPX's in-kernel LAPIC delivers virtual interrupts.
// Each virtual processor has its own host run-loop thread. WHPX creates APs
// with StartupSuspend set, then its emulated LAPIC releases them when the BSP
// sends the normal INIT/SIPI sequence.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ejpir/gantry/internal/vmm/boot"
	"github.com/ejpir/gantry/internal/vmm/devices"
	"golang.org/x/sys/windows"
)

var (
	winhv                = windows.NewLazySystemDLL("WinHvPlatform.dll")
	procGetCapability    = winhv.NewProc("WHvGetCapability")
	procCreatePartition  = winhv.NewProc("WHvCreatePartition")
	procSetPartitionProp = winhv.NewProc("WHvSetPartitionProperty")
	procSetupPartition   = winhv.NewProc("WHvSetupPartition")
	procDeletePartition  = winhv.NewProc("WHvDeletePartition")
	procMapGpaRange      = winhv.NewProc("WHvMapGpaRange")
	procUnmapGpaRange    = winhv.NewProc("WHvUnmapGpaRange")
	procCreateVP         = winhv.NewProc("WHvCreateVirtualProcessor")
	procDeleteVP         = winhv.NewProc("WHvDeleteVirtualProcessor")
	procCancelRunVP      = winhv.NewProc("WHvCancelRunVirtualProcessor")
	procRunVP            = winhv.NewProc("WHvRunVirtualProcessor")
	procGetVPRegs        = winhv.NewProc("WHvGetVirtualProcessorRegisters")
	procSetVPRegs        = winhv.NewProc("WHvSetVirtualProcessorRegisters")
	procRequestInterrupt = winhv.NewProc("WHvRequestInterrupt")
)

// register names (winhvplatformdefs.h)
const (
	whvRegRax    = 0x00
	whvRegRip    = 0x10
	whvRegRflags = 0x11
	whvRegEs     = 0x12
	whvRegCs     = 0x13
	whvRegSs     = 0x14
	whvRegDs     = 0x15
	whvRegFs     = 0x16
	whvRegGs     = 0x17
	whvRegIdtr   = 0x1a
	whvRegGdtr   = 0x1b
	whvRegCr0    = 0x1c
	whvRegCr3    = 0x1e
	whvRegCr4    = 0x1f
	whvRegEfer   = 0x2001
	// The split-PIC path injects a CPU interrupt directly, bypassing WHPX's
	// emulated LAPIC. Deliverability notifications make the vCPU exit once IF
	// and the interrupt-shadow state permit the next queued vector.
	whvRegPendingInterruption = 0x80000000
	whvRegDeliverability      = 0x80000004
)

// exit reasons
const (
	whvExitMemoryAccess  = 0x01
	whvExitIoPort        = 0x02
	whvExitUnrecoverable = 0x04
	whvExitInvalidVpReg  = 0x05
	whvExitInterruptWin  = 0x07
	whvExitHalt          = 0x08
	whvExitMsrAccess     = 0x1000
	whvExitCpuid         = 0x1001
	whvExitCanceled      = 0x2001
)

const (
	whvPropProcessorCount         = 0x00001fff
	whvPropLocalApicEmulationMode = 0x00001005
	whvCapProcessorClockFrequency = 0x00001004
	whvMapRead                    = 0x1
	whvMapWrite                   = 0x2
	whvMapExecute                 = 0x4
	whvExitContextSize            = 224
)

func whvCall(name string, proc *windows.LazyProc, args ...uintptr) error {
	r, _, _ := proc.Call(args...)
	if int32(r) != 0 {
		return fmt.Errorf("%s: HRESULT %#08x", name, uint32(r))
	}
	return nil
}

func whpxProcessorClockFrequency() (uint64, error) {
	var frequency uint64
	var written uint32
	if err := whvCall("WHvGetCapability(ProcessorClockFrequency)", procGetCapability,
		whvCapProcessorClockFrequency,
		uintptr(unsafe.Pointer(&frequency)), unsafe.Sizeof(frequency),
		uintptr(unsafe.Pointer(&written))); err != nil {
		return 0, err
	}
	if written != uint32(unsafe.Sizeof(frequency)) {
		return 0, fmt.Errorf("WHvGetCapability(ProcessorClockFrequency): wrote %d bytes, want %d",
			written, unsafe.Sizeof(frequency))
	}
	return frequency, nil
}

type whpxBackend struct {
	h          windows.Handle
	m          *Machine
	lifecycle  *nativeBackendLifecycle
	mu         sync.Mutex // serializes register file get/set per exit (cheap)
	nativeMu   sync.RWMutex
	cancelMu   sync.Mutex
	runMu      sync.Mutex
	runningVP  []bool
	picPending []uint32 // guarded by runMu; PIC serialization keeps this short
	picEpoch   uint64   // increments on enqueue; closes the stopped-to-running race
	exitCount  atomic.Uint64
	stats      struct {
		exits atomic.Uint64
		halt  atomic.Uint64
		mmio  atomic.Uint64
		other atomic.Uint64
	}
	profileMu      sync.Mutex
	profilePorts   []uint64
	profileMMIO    [2]uint64 // read, write
	profileGPAs    map[uint64]uint64
	profileSummary sync.Once

	partitionCreated bool
	mappedRAM        []boot.RAMRegion
	hotMemoryMapped  bool
	createdVPs       []bool
}

func (b *whpxBackend) runStats() runStats {
	return runStats{
		Exits: b.stats.exits.Load(),
		WFI:   b.stats.halt.Load(),
		MMIO:  b.stats.mmio.Load(),
		Other: b.stats.other.Load(),
	}
}

func (b *whpxBackend) cancelVCPUs() error {
	b.cancelMu.Lock()
	defer b.cancelMu.Unlock()
	b.runMu.Lock()
	running := make([]int, 0, len(b.runningVP))
	for vp, active := range b.runningVP {
		if active {
			running = append(running, vp)
		}
	}
	b.runMu.Unlock()
	var errs []error
	for _, vp := range running {
		if err := whvCall("WHvCancelRunVirtualProcessor", procCancelRunVP,
			uintptr(b.h), uintptr(vp), 0); err != nil {
			errs = append(errs, fmt.Errorf("cancel WHPX vCPU %d: %w", vp, err))
		}
	}
	return errors.Join(errs...)
}

func (b *whpxBackend) beginRun(vp uint32) bool {
	b.runMu.Lock()
	defer b.runMu.Unlock()
	if b.lifecycle.isStopping() {
		return false
	}
	b.runningVP[vp] = true
	return true
}

func (b *whpxBackend) endRun(vp uint32) {
	b.runMu.Lock()
	b.runningVP[vp] = false
	b.runMu.Unlock()
}

func (b *whpxBackend) picQueuedAfter(epoch uint64) bool {
	b.runMu.Lock()
	queued := b.picEpoch != epoch
	b.runMu.Unlock()
	return queued
}

// queuePICInterrupt requests a direct external-interrupt injection on the
// vCPU thread. WHvSetVirtualProcessorRegisters cannot safely race a running
// vCPU, so wake the run call and let runVPLoop publish the pending event.
func (b *whpxBackend) queuePICInterrupt(vector uint32) {
	if b.lifecycle.isStopping() {
		return
	}
	b.runMu.Lock()
	b.picPending = append(b.picPending, vector)
	b.picEpoch++
	running := len(b.runningVP) != 0 && b.runningVP[0]
	b.runMu.Unlock()
	if !running {
		return
	}
	b.nativeMu.RLock()
	defer b.nativeMu.RUnlock()
	if b.lifecycle.isStopping() {
		return
	}
	if err := whvCall("WHvCancelRunVirtualProcessor(PIC)", procCancelRunVP,
		uintptr(b.h), 0, 0); err != nil && devices.DebugIO {
		fmt.Printf("[whpx] wake for PIC v=%#x: %v\n", vector, err)
	}
}

func (b *whpxBackend) injectPICInterrupt(vp uint32, executionState uint16, rflags uint64) (uint64, error) {
	b.runMu.Lock()
	defer b.runMu.Unlock()
	if len(b.picPending) == 0 {
		return b.picEpoch, nil
	}
	// WHV_X64_VP_EXECUTION_STATE exposes InterruptionPending at bit 6 and
	// InterruptShadow at bit 7; RFLAGS.IF is bit 9. WHPX has one pending
	// interruption slot, so retain all vectors in our queue until that slot is
	// known to be available from the most recent exit context.
	ready := executionState&(1<<6|1<<7) == 0 && rflags&(1<<9) != 0
	names := make([]uint32, 0, 2)
	values := make([]uint64, 0, 2)
	var vector uint32
	if ready {
		vector = b.picPending[0]
		b.picPending = b.picPending[1:]
		// WHV_X64_PENDING_INTERRUPTION_REGISTER: pending bit 0, type
		// WHvX64PendingInterrupt (0) in bits 1..3, vector in bits 16..31.
		names = append(names, whvRegPendingInterruption)
		values = append(values, 1|uint64(byte(vector))<<16)
	}
	if len(b.picPending) != 0 {
		// InterruptNotification is bit 1 of
		// WHV_X64_DELIVERABILITY_NOTIFICATIONS_REGISTER.
		names = append(names, whvRegDeliverability)
		values = append(values, 1<<1)
	}
	if len(names) != 0 {
		// WHPX requires PendingInterruption to precede the notification register
		// when both are updated. A map made that order nondeterministic and the
		// Windows 2022 WHPX build faulted inside WinHvPlatform.dll rather than
		// returning an HRESULT when it received the reverse order.
		if err := b.writeGPRs(vp, names, values); err != nil {
			return b.picEpoch, fmt.Errorf("inject PIC vector %#x: %w", vector, err)
		}
	}
	if devices.DebugIO {
		if ready {
			fmt.Printf("[whpx] pending interruption v=%#x published\n", vector)
		} else {
			fmt.Printf("[whpx] PIC waiting for interrupt window state=%#x rflags=%#x\n", executionState, rflags)
		}
	}
	return b.picEpoch, nil
}

func (b *whpxBackend) releaseNative() error {
	b.nativeMu.Lock()
	defer b.nativeMu.Unlock()
	var errs []error
	for vp := len(b.createdVPs) - 1; vp >= 0; vp-- {
		if !b.createdVPs[vp] {
			continue
		}
		if err := whvCall("WHvDeleteVirtualProcessor", procDeleteVP,
			uintptr(b.h), uintptr(vp)); err != nil {
			errs = append(errs, fmt.Errorf("delete WHPX vCPU %d: %w", vp, err))
		}
		b.createdVPs[vp] = false
	}
	for index := len(b.mappedRAM) - 1; index >= 0; index-- {
		region := b.mappedRAM[index]
		if err := whvCall("WHvUnmapGpaRange", procUnmapGpaRange,
			uintptr(b.h), uintptr(region.GuestBase), uintptr(region.Size)); err != nil {
			errs = append(errs, fmt.Errorf("unmap WHPX guest RAM at GPA %#x: %w", region.GuestBase, err))
		}
	}
	b.mappedRAM = nil
	if b.partitionCreated {
		if err := whvCall("WHvDeletePartition", procDeletePartition, uintptr(b.h)); err != nil {
			errs = append(errs, fmt.Errorf("delete WHPX partition: %w", err))
		}
		b.partitionCreated = false
		b.h = 0
	}
	return errors.Join(errs...)
}

func (b *whpxBackend) Close() error {
	return b.lifecycle.close(b.cancelVCPUs, b.releaseNative)
}

// mapRAMRegionLocked commits a reserved host range before publishing its GPA
// mapping to WHPX. nativeMu must be held so teardown cannot delete the
// partition between the commit and WHvMapGpaRange.
func (b *whpxBackend) mapRAMRegionLocked(region boot.RAMRegion) error {
	if err := commitGuestRAM(b.m.ram, region.HostOffset, region.Size); err != nil {
		return err
	}
	if err := whvCall("WHvMapGpaRange", procMapGpaRange,
		uintptr(b.h), uintptr(unsafe.Pointer(&b.m.ram[region.HostOffset])), uintptr(region.GuestBase),
		uintptr(region.Size), whvMapRead|whvMapWrite|whvMapExecute); err != nil {
		return fmt.Errorf("WHvMapGpaRange(GPA %#x, size %d): %w", region.GuestBase, region.Size, err)
	}
	b.mappedRAM = append(b.mappedRAM, region)
	return nil
}

// mapHotMemory installs the virtio-mem tail after daemon readiness. The
// request advertised to Linux is sent only after this method returns, so the
// guest can never plug a block whose host pages or GPA mapping are absent.
func (b *whpxBackend) mapHotMemory() error {
	b.nativeMu.Lock()
	defer b.nativeMu.Unlock()
	if b.hotMemoryMapped {
		return nil
	}
	if !b.partitionCreated || b.h == 0 {
		return fmt.Errorf("map hot memory: WHPX partition is closed")
	}
	regions := b.m.ramRegions()
	if len(regions) != 2 || b.m.hotMem == nil {
		return fmt.Errorf("map hot memory: invalid x86 memory layout")
	}
	start := time.Now()
	if err := b.mapRAMRegionLocked(regions[1]); err != nil {
		return fmt.Errorf("map virtio-mem tail: %w", err)
	}
	b.hotMemoryMapped = true
	b.m.bootTiming.note("virtio-mem tail committed+mapped", start, time.Now())
	return nil
}

// whvRegValue is one WHV_REGISTER_VALUE (16 bytes).
type whvRegValue [16]byte

func segValue(base uint64, limit uint32, selector, attr uint16) whvRegValue {
	var v whvRegValue
	binary.LittleEndian.PutUint64(v[0:], base)
	binary.LittleEndian.PutUint32(v[8:], limit)
	binary.LittleEndian.PutUint16(v[12:], selector)
	binary.LittleEndian.PutUint16(v[14:], attr)
	return v
}

func tableValue(base uint64, limit uint16) whvRegValue {
	var v whvRegValue
	binary.LittleEndian.PutUint16(v[6:], limit)
	binary.LittleEndian.PutUint64(v[8:], base)
	return v
}

func u64Value(x uint64) whvRegValue {
	var v whvRegValue
	binary.LittleEndian.PutUint64(v[0:], x)
	return v
}

func (b *whpxBackend) setRegs(vp uint32, regs map[uint32]whvRegValue) error {
	names := make([]uint32, 0, len(regs))
	vals := make([]whvRegValue, 0, len(regs))
	for n, v := range regs {
		names = append(names, n)
		vals = append(vals, v)
	}
	return whvCall("WHvSetVirtualProcessorRegisters", procSetVPRegs,
		uintptr(b.h), uintptr(vp),
		uintptr(unsafe.Pointer(&names[0])), uintptr(len(names)),
		uintptr(unsafe.Pointer(&vals[0])))
}

func (b *whpxBackend) getRegs(vp uint32, names []uint32) ([]whvRegValue, error) {
	vals := make([]whvRegValue, len(names))
	err := whvCall("WHvGetVirtualProcessorRegisters", procGetVPRegs,
		uintptr(b.h), uintptr(vp),
		uintptr(unsafe.Pointer(&names[0])), uintptr(len(names)),
		uintptr(unsafe.Pointer(&vals[0])))
	return vals, err
}

func (b *whpxBackend) writeGPR(vp uint32, idx int, v uint64) error {
	return b.writeGPRs(vp, []uint32{uint32(idx)}, []uint64{v})
}

// writeGPRs updates a small explicit register set in one WHPX call. Exit
// handling is latency-sensitive: doing RAX and RIP as separate calls for every
// port/MMIO read made each guest access pay two host transitions.
func (b *whpxBackend) writeGPRs(vp uint32, names []uint32, values []uint64) error {
	if len(names) == 0 || len(names) != len(values) {
		return fmt.Errorf("invalid WHPX register update: %d names, %d values", len(names), len(values))
	}
	regs := make([]whvRegValue, len(values))
	for i, value := range values {
		regs[i] = u64Value(value)
	}
	return whvCall("WHvSetVirtualProcessorRegisters", procSetVPRegs,
		uintptr(b.h), uintptr(vp),
		uintptr(unsafe.Pointer(&names[0])), uintptr(len(names)),
		uintptr(unsafe.Pointer(&regs[0])))
}

// deliverInterrupt is the IO-APIC's delivery path into WHPX.
func (b *whpxBackend) deliverInterrupt(dest, vector uint32, level bool) {
	if b.lifecycle.isStopping() {
		return
	}
	b.nativeMu.RLock()
	defer b.nativeMu.RUnlock()
	if b.lifecycle.isStopping() {
		return
	}
	var ctrl [16]byte
	// Type=Fixed(0) @bits0-7, DestinationMode=Physical(0) @bits8-11,
	// TriggerMode=Edge(0)|Level(1) @bits12-15
	var c uint64
	if level {
		c = 1 << 12
	}
	binary.LittleEndian.PutUint64(ctrl[0:], c)
	binary.LittleEndian.PutUint32(ctrl[8:], dest)
	binary.LittleEndian.PutUint32(ctrl[12:], vector)
	if err := whvCall("WHvRequestInterrupt", procRequestInterrupt,
		uintptr(b.h), uintptr(unsafe.Pointer(&ctrl[0])), 16); err != nil {
		if devices.DebugIO {
			fmt.Printf("[whpx] interrupt v=%#x: %v\n", vector, err)
		}
	} else if devices.DebugIO {
		fmt.Printf("[whpx] interrupt v=%#x delivered\n", vector)
	}
}

// runGuest boots the prepared machine under WHPX (entry point for main).
type whpxPlatform struct{}

func (whpxPlatform) run(m *Machine) (resultErr error) {
	if m.arch != "amd64" {
		return fmt.Errorf("the WHPX backend boots x86-64 guests only (got %s)", m.arch)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var h windows.Handle
	if err := whvCall("WHvCreatePartition", procCreatePartition,
		uintptr(unsafe.Pointer(&h))); err != nil {
		return fmt.Errorf("%w (needs Windows 10 1809+ with the Hypervisor Platform enabled)", err)
	}
	b := &whpxBackend{
		h:                h,
		m:                m,
		lifecycle:        newNativeBackendLifecycle(m.vcpus),
		partitionCreated: true,
		createdVPs:       make([]bool, m.vcpus),
		runningVP:        make([]bool, m.vcpus),
	}
	if m.bootTiming.profiling() {
		b.profilePorts = make([]uint64, 1<<16)
		b.profileGPAs = make(map[uint64]uint64)
	}
	mainClaimed := false
	defer func() {
		if mainClaimed {
			b.lifecycle.workerDone()
		}
		if closeErr := b.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()

	prop := u64Value(uint64(m.vcpus))
	if err := whvCall("WHvSetPartitionProperty(ProcessorCount)", procSetPartitionProp,
		uintptr(h), uintptr(whvPropProcessorCount),
		uintptr(unsafe.Pointer(&prop)), 16); err != nil {
		return err
	}
	// Enable the emulated local APIC (WHvX64LocalApicEmulationModeXApic).
	// Without it WHvRequestInterrupt — the delivery path for the userspace
	// IO-APIC below — has nothing to deliver into, and guest LAPIC MMIO
	// reads at 0xfee00000 return zero while the MPS table advertises one.
	apicMode := u64Value(1) // WHvX64LocalApicEmulationModeXApic
	if err := whvCall("WHvSetPartitionProperty(LocalApicEmulationMode)", procSetPartitionProp,
		uintptr(h), uintptr(whvPropLocalApicEmulationMode),
		uintptr(unsafe.Pointer(&apicMode)), 16); err != nil {
		return err
	}
	if err := whvCall("WHvSetupPartition", procSetupPartition, uintptr(h)); err != nil {
		return err
	}
	regions := m.ramRegions()
	if m.hotMemDeferred {
		regions = regions[:1]
	}
	for _, region := range regions {
		if err := b.mapRAMRegionLocked(region); err != nil {
			return err
		}
	}

	// Stable default: userspace IO-APIC delivering into WHPX's emulated LAPIC.
	// The experimental PIC path is opt-in because its edge/in-service model is
	// not yet complete enough for sustained virtio interrupt delivery.
	// Keep the register-visible ID identical to the one writeMPS publishes.
	// A mismatch makes Linux repeatedly repair and re-read the IO-APIC ID,
	// which is particularly expensive because every access exits through WHPX.
	m.x86.ioapic = devices.NewIOAPIC(uint32(m.vcpus+1), b.deliverInterrupt)
	if os.Getenv("GANTRY_WHPX_PIC") != "" {
		m.x86.pic.SetDeliver(b.queuePICInterrupt)
		m.interrupts.set(func(irq int, level bool) {
			m.x86.ioapic.Raise(boot.ISAIRQGSI(irq), level)
			// Diagnostic opt-out for the legacy PIT edge. Once Linux switches
			// to WHPX's emulated LAPIC timer it can leave a concurrently queued
			// PIC IRQ0 unacknowledged, which then blocks every lower-priority
			// virtio interrupt. Automatic TSC calibration makes that PIT edge
			// unnecessary on the tested WHPX path.
			if irq != 0 || os.Getenv("GANTRY_WHPX_PIC_NOPIT") == "" {
				m.x86.pic.Raise(irq, level)
			}
		})
	} else {
		m.interrupts.set(func(irq int, level bool) { m.x86.ioapic.Raise(boot.ISAIRQGSI(irq), level) })
	}

	for i := 0; i < m.vcpus; i++ {
		if err := whvCall("WHvCreateVirtualProcessor", procCreateVP,
			uintptr(h), uintptr(i), 0); err != nil {
			return fmt.Errorf("WHvCreateVirtualProcessor(%d): %w", i, err)
		}
		b.createdVPs[i] = true
	}
	if !b.lifecycle.claimWorker() {
		return errMachineClosed
	}
	mainClaimed = true
	if err := m.adoptBackend(b); err != nil {
		return err
	}

	return b.bootLoop()
}

func (b *whpxBackend) bootLoop() error {
	m := b.m
	code := segValue(0, 0xffffffff, 0x10, 0xa09b) // present, S, L, G, exec/read
	data := segValue(0, 0xffffffff, 0x18, 0x8093) // present, S, G, rw
	if err := b.setRegs(0, map[uint32]whvRegValue{
		whvRegRip:    u64Value(m.entry),
		whvRegRsi:    u64Value(boot.ZeroPage),
		whvRegRsp:    u64Value(boot.StackTop - 0x10),
		whvRegRflags: u64Value(0x2),
		whvRegCs:     code,
		whvRegDs:     data,
		whvRegEs:     data,
		whvRegSs:     data,
		whvRegFs:     data,
		whvRegGs:     data,
		whvRegCr0:    u64Value(0x80010033),
		whvRegCr3:    u64Value(boot.PML4),
		whvRegCr4:    u64Value(0x20),
		whvRegEfer:   u64Value(0x500),
		whvRegGdtr:   tableValue(boot.GDT, 4*8-1),
		whvRegIdtr:   tableValue(0, 0xffff),
	}); err != nil {
		return fmt.Errorf("initial BSP state: %w", err)
	}

	fmt.Printf("booting guest under WHPX/x86-64 (%d vCPU max)\n", m.vcpus)
	fmt.Println("------------------------------------------------")

	if m.consoleStdin {
		go m.x86.uartIO.StdinPump(m.stdinDone)
		defer close(m.stdinDone)
	}
	m.bootTiming.setRunStats(b.runStats)
	m.bootTiming.start("vCPU entered WHPX")
	if err := b.startSecondaryVCPUs(); err != nil {
		return err
	}
	return b.runVPLoop(0)
}

// startSecondaryVCPUs enters every WHPX AP on its own locked OS thread. APs
// initially block in WHPX with StartupSuspend set; Linux's INIT/SIPI sequence
// through the emulated LAPIC supplies their actual startup state.
func (b *whpxBackend) startSecondaryVCPUs() error {
	started := make(chan bool, max(0, b.m.vcpus-1))
	for id := 1; id < b.m.vcpus; id++ {
		go func(vp uint32) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if !b.lifecycle.claimWorker() {
				started <- false
				return
			}
			defer b.lifecycle.workerDone()
			started <- true
			if b.lifecycle.isStopping() {
				return
			}
			b.failVCPU(vp, b.runVPLoop(vp))
		}(uint32(id))
	}
	for range b.m.vcpus - 1 {
		if !<-started {
			return errMachineClosed
		}
	}
	return nil
}

func (b *whpxBackend) failVCPU(vp uint32, err error) {
	if err == nil || b.lifecycle.isStopping() {
		return
	}
	workerErr := fmt.Errorf("WHPX vCPU %d: %w", vp, err)
	b.lifecycle.recordError(workerErr)
	fmt.Fprintf(os.Stderr, "\n[cpu%d] run loop: %v\n", vp, err)
	b.lifecycle.stop()
	if cancelErr := b.cancelVCPUs(); cancelErr != nil {
		b.lifecycle.recordError(cancelErr)
	}
}

const (
	whvRegRsi = 0x06
	whvRegRsp = 0x04
)

func (b *whpxBackend) runVPLoop(vp uint32) error {
	buf := make([]byte, whvExitContextSize)
	var executionState uint16
	rflags := uint64(2) // initial BSP RFLAGS; interrupts start disabled
	for {
		var picEpoch uint64
		var err error
		if vp == 0 {
			picEpoch, err = b.injectPICInterrupt(vp, executionState, rflags)
			if err != nil {
				return err
			}
		}
		if !b.beginRun(vp) {
			return nil
		}
		// Close the queue-before-beginRun race without mistaking an existing
		// backlog for a new arrival. A backlog must run one event at a time so
		// WHPX can consume its single PendingEvent slot.
		if vp == 0 && b.picQueuedAfter(picEpoch) {
			b.endRun(vp)
			continue
		}
		var started time.Time
		if b.m.bootTiming.profiling() {
			started = time.Now()
		}
		err = whvCall("WHvRunVirtualProcessor", procRunVP,
			uintptr(b.h), uintptr(vp),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		var ran time.Duration
		if !started.IsZero() {
			ran = time.Since(started)
		}
		b.endRun(vp)
		if err != nil {
			if b.lifecycle.isStopping() {
				return nil
			}
			return fmt.Errorf("WHvRunVirtualProcessor: %w", err)
		}
		// Every x64 exit carries this common VP context. Retain exactly the
		// interruptibility fields needed before publishing the next PIC vector.
		executionState = binary.LittleEndian.Uint16(buf[8:])
		rflags = binary.LittleEndian.Uint64(buf[40:])
		reason := binary.LittleEndian.Uint32(buf[0:])
		if b.m.bootTiming.profiling() {
			index := int(b.stats.exits.Add(1))
			detail := ""
			switch reason {
			case whvExitHalt:
				b.stats.halt.Add(1)
			case whvExitMemoryAccess:
				b.stats.mmio.Add(1)
				detail = fmt.Sprintf(", gpa %#x", binary.LittleEndian.Uint64(buf[72:]))
			default:
				b.stats.other.Add(1)
				if reason == whvExitIoPort {
					detail = fmt.Sprintf(", port %#x", binary.LittleEndian.Uint16(buf[72:]))
				}
			}
			if index <= 64 {
				b.m.bootTiming.traceExit(index, ran, reason, 0, detail)
			}
		}
		if devices.DebugIO {
			exitCount := b.exitCount.Add(1)
			if exitCount <= 500 || exitCount%100000 == 0 {
				reason := binary.LittleEndian.Uint32(buf[0:])
				if reason == whvExitIoPort {
					fmt.Printf("[whpx] exit io rip=%#x port=%#x info=%#x len=%d/%d (n=%d)\n",
						binary.LittleEndian.Uint64(buf[32:]),
						binary.LittleEndian.Uint16(buf[72:]),
						binary.LittleEndian.Uint32(buf[68:]),
						buf[10]&0x0f, buf[48], exitCount)
				} else {
					fmt.Printf("[whpx] exit %#x rip=%#x (n=%d)\n", reason,
						binary.LittleEndian.Uint64(buf[32:]), exitCount)
				}
			}
		}
		switch reason {
		case whvExitMemoryAccess:
			if err := b.handleMMIOExit(vp, buf); err != nil {
				return err
			}
		case whvExitIoPort:
			if b.profilePorts != nil {
				b.profileMu.Lock()
				b.profilePorts[binary.LittleEndian.Uint16(buf[72:])]++
				b.profileMu.Unlock()
			}
			if err := b.handleIOExit(vp, buf); err != nil {
				return err
			}
		case whvExitHalt:
			// halt: re-enter and block until the next interrupt;
		case whvExitCanceled:
			if b.lifecycle.isStopping() {
				return nil
			}
		case whvExitInterruptWin:
			// A queued PIC vector is now deliverable; the next loop publishes it.
		case whvExitUnrecoverable:
			b.m.stdoutFlush()
			rip := binary.LittleEndian.Uint64(buf[32:])
			return fmt.Errorf("unrecoverable guest exception (triple fault) rip=%#x", rip)
		case whvExitInvalidVpReg:
			return fmt.Errorf("WHvRunVpExitReasonInvalidVpRegisterValue (bad initial state?)")
		case whvExitMsrAccess, whvExitCpuid:
			if devices.DebugIO {
				fmt.Printf("[whpx] exit %d (ignored)\n", binary.LittleEndian.Uint32(buf[0:]))
			}
		default:
			// interrupt window, eoi, hypercall, rdtsc: nothing to do
		}
		if b.m.bootTiming.bootComplete() {
			b.profileSummary.Do(b.printBootProfileSummary)
		}
	}
}

func (b *whpxBackend) printBootProfileSummary() {
	if b.profilePorts == nil {
		return
	}
	b.profileMu.Lock()
	defer b.profileMu.Unlock()
	fmt.Printf("boot-profile: WHPX MMIO reads=%d writes=%d; top I/O ports:", b.profileMMIO[0], b.profileMMIO[1])
	for range 16 {
		port, count := -1, uint64(0)
		for candidate, candidateCount := range b.profilePorts {
			if candidateCount > count {
				port, count = candidate, candidateCount
			}
		}
		if port < 0 || count == 0 {
			break
		}
		fmt.Printf(" %#x=%d", port, count)
		b.profilePorts[port] = 0
	}
	fmt.Println()
	fmt.Print("boot-profile: top MMIO addresses:")
	for range 16 {
		var page, count uint64
		for candidate, candidateCount := range b.profileGPAs {
			if candidateCount > count {
				page, count = candidate, candidateCount
			}
		}
		if count == 0 {
			break
		}
		fmt.Printf(" %#x=%d", page, count)
		delete(b.profileGPAs, page)
	}
	fmt.Println()
}

// handleMMIOExit emulates one MemoryAccess exit: decode the instruction,
// service the device access, fill/read registers, advance RIP.
func (b *whpxBackend) handleMMIOExit(vp uint32, buf []byte) error {
	m := b.m
	// The common exit context's InstructionLength can be shorter than the
	// instruction that caused a MemoryAccess exit. In particular, current
	// WHPX releases have reported one byte for a two-byte `mov r/m32,r32`.
	// The memory-access context still carries the complete 16-byte instruction
	// window, so give the decoder the architectural 15-byte maximum and trust
	// op.Length for the RIP advance. The decoder ignores trailing bytes.
	instr := buf[52 : 52+15]
	gpa := binary.LittleEndian.Uint64(buf[72:])
	if b.profileGPAs != nil {
		b.profileMu.Lock()
		b.profileGPAs[gpa]++
		b.profileMu.Unlock()
	}

	op, err := devices.DecodeMMIO(instr)
	if err != nil {
		return fmt.Errorf("mmio @ %#x: undecodable instruction % x: %w", gpa, instr, err)
	}

	if b.profilePorts != nil {
		b.profileMu.Lock()
		if op.IsWrite {
			b.profileMMIO[1]++
		} else {
			b.profileMMIO[0]++
		}
		b.profileMu.Unlock()
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	// The exit already supplies the GPA, and the decoder identifies the one
	// source/destination GPR. Do not fetch all 16 GPRs on every virtio access.
	// Reads need no old register value; immediate writes need no register at
	// all. Register writes fetch exactly their source in one WHPX call.
	var regValue uint64
	if op.IsWrite && !op.ImmOK {
		values, err := b.getRegs(vp, []uint32{uint32(op.Reg)})
		if err != nil {
			return err
		}
		regValue = binary.LittleEndian.Uint64(values[0][0:])
	}
	getReg := func(int) uint64 { return regValue }
	setReg := func(_ int, v uint64) { regValue = v }

	devRead := func(width int) uint64 {
		var v uint64
		for off := 0; off < width; off += 4 { // devices are 32-bit; split wider
			v |= uint64(m.handleMMIO(false, gpa+uint64(off), nil, 4)) << (8 * off)
		}
		return v
	}
	devWrite := func(width int, val uint64) {
		var tmp [8]byte
		binary.LittleEndian.PutUint64(tmp[:], val)
		for off := 0; off < width; off += 4 {
			m.handleMMIO(true, gpa+uint64(off), tmp[off:off+4], 4)
		}
	}
	devices.ApplyMMIO(op, getReg, setReg, devRead, devWrite)

	// Commit the MMIO read result and advanced RIP together. Writes only need
	// RIP; combining read updates removes one WHPX host transition per access.
	rip := binary.LittleEndian.Uint64(buf[32:]) + uint64(op.Length)
	if op.IsWrite {
		return b.writeGPR(vp, whvRegRip, rip)
	}
	return b.writeGPRs(vp,
		[]uint32{uint32(op.Reg), whvRegRip},
		[]uint64{regValue, rip})
}

// handleIOExit services one port-I/O exit (serial/CMOS/PIT/PIC/delay).
func (b *whpxBackend) handleIOExit(vp uint32, buf []byte) error {
	m := b.m
	accessInfo := binary.LittleEndian.Uint32(buf[68:])
	isWrite := accessInfo&1 != 0
	size := int((accessInfo >> 1) & 7)
	port := uint16(binary.LittleEndian.Uint16(buf[72:]))
	rax := binary.LittleEndian.Uint64(buf[80:])
	if accessInfo&0x30 != 0 { // string/rep: not used against our devices
		return fmt.Errorf("string I/O to port %#x (unsupported)", port)
	}

	// guest-initiated reset
	if isWrite && (port == 0xcf9 || (port == 0x64 && byte(rax) == 0xfe)) {
		b.m.stdoutFlush()
		fmt.Println("\n------------------------------------------------")
		fmt.Println("guest rebooted (reset port); exiting")
		return ErrGuestReset
	}

	// WHPX does not complete the intercepted IN/OUT: RIP must be advanced
	// past the instruction manually. The length comes from
	// VpContext.InstructionLength (buf[10], low nibble): the IoPort
	// context's InstructionByteCount (buf[48]) is 0 on current WHPX
	// releases, which looped the guest on one port access forever (field
	// finding from the first real hardware run).
	advance := func() error {
		instrLen := int(buf[10] & 0x0f)
		if instrLen == 0 {
			instrLen = int(buf[48])
		}
		if instrLen == 0 {
			return fmt.Errorf("io exit @ %#x: zero instruction length", binary.LittleEndian.Uint64(buf[32:]))
		}
		rip := binary.LittleEndian.Uint64(buf[32:])
		return b.writeGPR(vp, whvRegRip, rip+uint64(instrLen))
	}

	if isWrite {
		m.handleIO(true, port, uint32(rax), size)
		return advance()
	}
	v := m.handleIO(false, port, 0, size)
	// IN modifies only AL/AX/EAX of RAX
	switch size {
	case 1:
		rax = rax&^0xff | uint64(byte(v))
	case 2:
		rax = rax&^0xffff | uint64(uint16(v))
	default:
		rax = uint64(v)
	}
	// IN changes RAX and completes at the following RIP. Publish both in one
	// WHPX call instead of paying two host transitions for every port read.
	instrLen := int(buf[10] & 0x0f)
	if instrLen == 0 {
		instrLen = int(buf[48])
	}
	if instrLen == 0 {
		return fmt.Errorf("io exit @ %#x: zero instruction length", binary.LittleEndian.Uint64(buf[32:]))
	}
	rip := binary.LittleEndian.Uint64(buf[32:]) + uint64(instrLen)
	return b.writeGPRs(vp,
		[]uint32{whvRegRax, whvRegRip},
		[]uint64{rax, rip})
}

// platformBackend selects the hypervisor backend for this build target.
func platformBackend() backend { return whpxPlatform{} }
