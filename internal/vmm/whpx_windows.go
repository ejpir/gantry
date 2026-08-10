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
// Resource validation admits one BSP until INIT/SIPI AP startup is supported.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	winhv                = windows.NewLazySystemDLL("WinHvPlatform.dll")
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
)

// exit reasons
const (
	whvExitMemoryAccess  = 0x01
	whvExitIoPort        = 0x02
	whvExitUnrecoverable = 0x04
	whvExitInvalidVpReg  = 0x05
	whvExitHalt          = 0x08
	whvExitMsrAccess     = 0x1000
	whvExitCpuid         = 0x1001
	whvExitCanceled      = 0x2001
)

const (
	whvPropProcessorCount         = 0x00001fff
	whvPropLocalApicEmulationMode = 0x00001005
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

type whpxBackend struct {
	h         windows.Handle
	m         *Machine
	lifecycle *nativeBackendLifecycle
	mu        sync.Mutex // serializes register file get/set per exit (cheap)
	nativeMu  sync.RWMutex
	runMu     sync.Mutex
	runningVP []bool

	partitionCreated bool
	mapped           bool
	createdVPs       []bool
}

func (b *whpxBackend) cancelVCPUs() error {
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
	if b.mapped {
		if err := whvCall("WHvUnmapGpaRange", procUnmapGpaRange,
			uintptr(b.h), 0, uintptr(len(b.m.ram))); err != nil {
			errs = append(errs, fmt.Errorf("unmap WHPX guest RAM: %w", err))
		}
		b.mapped = false
	}
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

// gprs is a scratch register file (Rax..R15 = indices 0..15, matching both
// the WHV register enum and the x86 ModRM encoding).
func (b *whpxBackend) readGPRs(vp uint32) ([16]uint64, error) {
	names := make([]uint32, 16)
	for i := range names {
		names[i] = uint32(i)
	}
	vals, err := b.getRegs(vp, names)
	var g [16]uint64
	for i := range vals {
		g[i] = binary.LittleEndian.Uint64(vals[i][0:])
	}
	return g, err
}

func (b *whpxBackend) writeGPR(vp uint32, idx int, v uint64) error {
	return b.setRegs(vp, map[uint32]whvRegValue{uint32(idx): u64Value(v)})
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
		uintptr(b.h), uintptr(unsafe.Pointer(&ctrl[0])), 16); err != nil && dbgIO {
		fmt.Printf("[whpx] interrupt v=%#x: %v\n", vector, err)
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
	if err := whvCall("WHvMapGpaRange", procMapGpaRange,
		uintptr(h), uintptr(unsafe.Pointer(&m.ram[0])), 0,
		uintptr(len(m.ram)), whvMapRead|whvMapWrite|whvMapExecute); err != nil {
		return fmt.Errorf("WHvMapGpaRange: %w", err)
	}
	b.mapped = true

	// userspace irqchip: IO-APIC delivering via WHvRequestInterrupt
	m.x86.ioapic = newIOApic(b.deliverInterrupt)
	m.interrupts.set(func(irq int, level bool) { m.x86.ioapic.raise(irq, level) })

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
		whvRegRsi:    u64Value(x86ZeroPage),
		whvRegRsp:    u64Value(x86StackTop - 0x10),
		whvRegRflags: u64Value(0x2),
		whvRegCs:     code,
		whvRegDs:     data,
		whvRegEs:     data,
		whvRegSs:     data,
		whvRegFs:     data,
		whvRegGs:     data,
		whvRegCr0:    u64Value(0x80010033),
		whvRegCr3:    u64Value(x86PML4),
		whvRegCr4:    u64Value(0x20),
		whvRegEfer:   u64Value(0x500),
		whvRegGdtr:   tableValue(x86GDT, 4*8-1),
		whvRegIdtr:   tableValue(0, 0xffff),
	}); err != nil {
		return fmt.Errorf("initial BSP state: %w", err)
	}

	fmt.Printf("booting guest under WHPX/x86-64 (%d vCPU max)\n", m.vcpus)
	fmt.Println("------------------------------------------------")

	if m.consoleStdin {
		go m.x86.uartIO.stdinPump(m.stdinDone)
		defer close(m.stdinDone)
	}
	return b.runVPLoop(0)
}

const (
	whvRegRsi = 0x06
	whvRegRsp = 0x04
)

func (b *whpxBackend) runVPLoop(vp uint32) error {
	buf := make([]byte, whvExitContextSize)
	for {
		if !b.beginRun(vp) {
			return nil
		}
		err := whvCall("WHvRunVirtualProcessor", procRunVP,
			uintptr(b.h), uintptr(vp),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		b.endRun(vp)
		if err != nil {
			if b.lifecycle.isStopping() {
				return nil
			}
			return fmt.Errorf("WHvRunVirtualProcessor: %w", err)
		}
		switch binary.LittleEndian.Uint32(buf[0:]) {
		case whvExitMemoryAccess:
			if err := b.handleMMIOExit(vp, buf); err != nil {
				return err
			}
		case whvExitIoPort:
			if err := b.handleIOExit(vp, buf); err != nil {
				return err
			}
		case whvExitHalt:
			// halt: re-enter and block until the next interrupt;
		case whvExitCanceled:
			if b.lifecycle.isStopping() {
				return nil
			}
		case whvExitUnrecoverable:
			b.m.stdoutFlush()
			rip := binary.LittleEndian.Uint64(buf[32:])
			return fmt.Errorf("unrecoverable guest exception (triple fault) rip=%#x", rip)
		case whvExitInvalidVpReg:
			return fmt.Errorf("WHvRunVpExitReasonInvalidVpRegisterValue (bad initial state?)")
		case whvExitMsrAccess, whvExitCpuid:
			if dbgIO {
				fmt.Printf("[whpx] exit %d (ignored)\n", binary.LittleEndian.Uint32(buf[0:]))
			}
		default:
			// interrupt window, eoi, hypercall, rdtsc: nothing to do
		}
	}
}

// handleMMIOExit emulates one MemoryAccess exit: decode the instruction,
// service the device access, fill/read registers, advance RIP.
func (b *whpxBackend) handleMMIOExit(vp uint32, buf []byte) error {
	m := b.m
	instrLen := int(buf[48])
	if instrLen < 1 || instrLen > 15 {
		return fmt.Errorf("bad instruction length %d", instrLen)
	}
	instr := buf[52 : 52+instrLen]
	gpa := binary.LittleEndian.Uint64(buf[72:])

	op, err := decodeX86MMIO(instr)
	if err != nil {
		return fmt.Errorf("mmio @ %#x: undecodable instruction % x: %w", gpa, instr, err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	gprs, err := b.readGPRs(vp)
	if err != nil {
		return err
	}
	getReg := func(i int) uint64 { return gprs[i] }
	setReg := func(i int, v uint64) { gprs[i] = v }

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
	applyX86MMIO(op, getReg, setReg, devRead, devWrite)

	// write back changed registers + advanced RIP
	if !op.isWrite {
		if err := b.writeGPR(vp, op.reg, gprs[op.reg]); err != nil {
			return err
		}
	}
	rip := binary.LittleEndian.Uint64(buf[32:])
	return b.writeGPR(vp, whvRegRip, rip+uint64(op.length))
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
	// past the instruction manually (InstructionByteCount @ union offset 0
	// of the exit context, i.e. buf[48]). Without this the guest
	// re-executes the same port access forever — the CMOS/PIT reads in
	// early boot hang silently before the console comes up.
	advance := func() error {
		rip := binary.LittleEndian.Uint64(buf[32:])
		return b.writeGPR(vp, whvRegRip, rip+uint64(buf[48]))
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
	if err := b.writeGPR(vp, whvRegRax, rax); err != nil {
		return err
	}
	return advance()
}

// platformBackend selects the hypervisor backend for this build target.
func platformBackend() backend { return whpxPlatform{} }
