package virtio

import (
	"encoding/binary"
	"fmt"
	"sync"
)

// virtio-mmio transport (version 2) + split virtqueues.
//
// Each device gets a 0x200-byte MMIO region and one GIC SPI. Layout follows
// QEMU's "virt" machine so the same FDT style works everywhere:
//
//	dev 0: 0x0a000000 irq 48 (SPI 16)   dev 1: 0x0a000200 irq 49 (SPI 17) ...
const (
	MMIOBaseArm64   = 0x0a000000
	MMIOStrideArm64 = 0x200
	MMIOIRQArm64    = 48 // INTID of SPI 16
	MMIOSize        = 0x200

	virtioMagic = 0x74726976 // "virt"

	// feature bits
	virtioFVersion1 = 32

	// status bits
	virtioStatusAcknowledge = 1
	virtioStatusDriver      = 2
	virtioStatusDriverOK    = 4
	virtioStatusFeaturesOK  = 8

	// interrupt status bits
	virtioIntUsedBuffer = 1
	virtioIntConfig     = 2

	// descriptor flags
	vringDescFNext     = 1
	vringDescFWrite    = 2
	vringDescFIndirect = 4

	virtqSize = 128
)

// mem is the device's view of guest physical memory.
type mem interface {
	readAt(addr uint64, p []byte) error
	writeAt(addr uint64, p []byte) error
	size() uint64
	contains(addr, n uint64) bool
}

// RAM implements mem over the VM's RAM slice. base is the guest
// physical address of ram[0] (0x40000000 on arm64, 0 on x86-64).
type RAM struct {
	mu   sync.RWMutex
	ram  []byte
	base uint64
}

// NewRAM wraps the guest RAM slice; base is the guest physical address of
// ram[0] (0x40000000 on arm64, 0 on x86-64).
func NewRAM(ram []byte, base uint64) *RAM { return &RAM{ram: ram, base: base} }

func (m *RAM) size() uint64 { return uint64(len(m.ram)) }

// contains reports whether [addr, addr+n) lies fully inside guest RAM.
func (m *RAM) contains(addr, n uint64) bool {
	return addr >= m.base && n <= uint64(len(m.ram)) && addr-m.base <= uint64(len(m.ram))-n
}

func (m *RAM) off(addr uint64) (uint64, error) {
	if addr < m.base || addr >= m.base+uint64(len(m.ram)) {
		return 0, fmt.Errorf("guest addr %#x outside RAM", addr)
	}
	return addr - m.base, nil
}

// Guest RAM is shared between vCPU exit handlers and every device goroutine.
// The RWMutex serializes access so the race detector (and future SMP device
// paths) see a coherent memory instead of raw slice races; it is leaf-level
// (held only for the copy), so it can't deadlock against device locks.
func (m *RAM) readAt(addr uint64, p []byte) error {
	o, err := m.off(addr)
	if err != nil {
		return err
	}
	if o+uint64(len(p)) > uint64(len(m.ram)) {
		return fmt.Errorf("guest read %#x+%d overflows RAM", addr, len(p))
	}
	m.mu.RLock()
	copy(p, m.ram[o:o+uint64(len(p))])
	m.mu.RUnlock()
	return nil
}
func (m *RAM) writeAt(addr uint64, p []byte) error {
	o, err := m.off(addr)
	if err != nil {
		return err
	}
	if o+uint64(len(p)) > uint64(len(m.ram)) {
		return fmt.Errorf("guest write %#x+%d overflows RAM", addr, len(p))
	}
	m.mu.Lock()
	copy(m.ram[o:o+uint64(len(p))], p)
	m.mu.Unlock()
	return nil
}

// virtq is one split virtqueue as seen from the device side.
type virtq struct {
	ready     bool
	num       uint32
	descAddr  uint64
	availAddr uint64
	usedAddr  uint64
	lastAvail uint16 // next avail index to consume
}

// numValid reports whether the guest programmed a usable ring size.
// Ring index math does % uint16(q.num); num==0 would divide by zero.
func (q *virtq) numValid() bool { return q.num >= 1 && q.num <= virtqSize }

type desc struct {
	addr  uint64
	len   uint32
	flags uint16
	next  uint16
}

// Device is implemented by each emulated device (blk, vsock).
type Device interface {
	deviceID() uint32
	features() uint64 // device-specific bits; VERSION_1 is OR'd in by the core
	numQueues() int
	configRead(off uint64, p []byte)  // device config space
	configWrite(off uint64, p []byte) // rarely used
	reset()
	// handleQueue is called (with dev.mu held) when the guest notifies queue q.
	handleQueue(q int)
	// setCore wires the transport into the device (NewCoreAt; device
	// goroutines must not run before this — see NewCoreAt's start hook).
	setCore(c *Core)
}

// Core is the transport state machine shared by all devices.
type Core struct {
	mu      sync.Mutex
	dev     Device
	mem     mem
	irq     int
	irqLine func(irq int, level bool)
	name    string
	base    uint64

	featureSel uint32
	driverFeat uint64
	driverSel  uint32
	queueSel   int
	queues     []virtq
	status     uint32
	isr        uint32
	gen        uint32
}

// NewCoreAt attaches dev at an explicit MMIO base and IRQ (the
// machine picks arch-appropriate values; see machine.addVirtio).
func NewCoreAt(dev Device, mem *RAM, base uint64, irq int, irqLine func(int, bool), name string) *Core {
	c := &Core{
		dev:     dev,
		mem:     mem,
		irq:     irq,
		irqLine: irqLine,
		name:    name,
		base:    base,
		queues:  make([]virtq, dev.numQueues()),
	}
	dev.setCore(c)
	if s, ok := dev.(interface{ start() }); ok {
		s.start()
	}
	return c
}

// Base/IRQ report the slot assignment (kernel-cmdline/FDT enumeration).
func (c *Core) Base() uint64 { return c.base }
func (c *Core) IRQ() int     { return c.irq }

// ---------------- MMIO register interface (u32 accesses) --------------------

func (c *Core) MMIORead(off uint64, length uint32) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if off >= 0x100 { // device config space, arbitrary widths
		buf := make([]byte, length)
		c.dev.configRead(off-0x100, buf)
		var v uint32
		for i := uint32(0); i < length && i < 4; i++ {
			v |= uint32(buf[i]) << (8 * i)
		}
		return v
	}
	switch off {
	case 0x000:
		return virtioMagic
	case 0x004:
		return 2 // version
	case 0x008:
		return c.dev.deviceID()
	case 0x00c:
		return 0x4d564e // "NVM" vendor
	case 0x010: // DeviceFeatures
		f := c.dev.features() | (1 << virtioFVersion1)
		if c.featureSel == 1 {
			return uint32(f >> 32)
		}
		return uint32(f)
	case 0x034: // QueueNumMax
		return virtqSize
	case 0x044: // QueueReady
		if c.queueSel < len(c.queues) && c.queues[c.queueSel].ready {
			return 1
		}
		return 0
	case 0x060: // InterruptStatus
		return c.isr
	case 0x070: // Status
		return c.status
	case 0x0fc: // ConfigGeneration
		return c.gen
	case 0x0b0, 0x0b4: // SHMLenLow / SHMLenHigh
		// No shared memory regions (e.g. no virtio-fs DAX window). The
		// kernel treats an all-ones length as "absent" (libkrun semantics);
		// a zero length is a present zero-sized window and makes the
		// virtio-fs probe fail with EBUSY.
		return 0xffffffff
	case 0x0b8, 0x0bc: // SHMBaseLow / SHMBaseHigh
		return 0
	}
	return 0
}

func (c *Core) MMIOWrite(off uint64, val uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case off >= 0x100:
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], val)
		c.dev.configWrite(off-0x100, buf[:])
	case off == 0x014: // DeviceFeaturesSel
		c.featureSel = val
	case off == 0x020: // DriverFeatures
		if c.driverSel == 1 {
			c.driverFeat = c.driverFeat&0xffffffff | uint64(val)<<32
		} else {
			c.driverFeat = c.driverFeat&0xffffffff00000000 | uint64(val)
		}
	case off == 0x024: // DriverFeaturesSel
		c.driverSel = val
	case off == 0x030: // QueueSel
		if int(val) < len(c.queues) {
			c.queueSel = int(val)
		}
	case off == 0x038: // QueueNum — clamp: an untrusted guest could write
		// 0 (divide-by-zero in the ring index math) or >QueueNumMax.
		if val >= 1 && val <= virtqSize {
			c.queues[c.queueSel].num = val
		}
	case off == 0x044: // QueueReady — refuse to arm a queue with no valid size
		c.queues[c.queueSel].ready = val == 1 && c.queues[c.queueSel].numValid()
	case off == 0x050: // QueueNotify
		if int(val) < len(c.queues) && c.queues[val].ready {
			c.dev.handleQueue(int(val))
		}
	case off == 0x064: // InterruptACK
		c.isr &^= val
		if c.isr == 0 {
			// The irq line follows the device's pending state; lowering it
			// matters on edge-triggered setups (x86 IO-APIC): a later raise
			// must produce a fresh edge.
			c.irqLine(c.irq, false)
		}
		// note: no line deassert — hv_gic interrupts are trigger-only;
		// the guest's EOI clears the pending state (libkrun semantics).
	case off == 0x070: // Status
		if val == 0 {
			c.status = 0
			c.isr = 0
			c.queueSel = 0
			for i := range c.queues {
				c.queues[i] = virtq{}
			}
			c.dev.reset()
			return
		}
		c.status |= val
	case off == 0x080: // QueueDescLow
		q := &c.queues[c.queueSel]
		q.descAddr = q.descAddr&0xffffffff00000000 | uint64(val)
	case off == 0x084: // QueueDescHigh
		q := &c.queues[c.queueSel]
		q.descAddr = q.descAddr&0xffffffff | uint64(val)<<32
	case off == 0x090: // QueueAvailLow
		q := &c.queues[c.queueSel]
		q.availAddr = q.availAddr&0xffffffff00000000 | uint64(val)
	case off == 0x094: // QueueAvailHigh
		q := &c.queues[c.queueSel]
		q.availAddr = q.availAddr&0xffffffff | uint64(val)<<32
	case off == 0x0a0: // QueueUsedLow
		q := &c.queues[c.queueSel]
		q.usedAddr = q.usedAddr&0xffffffff00000000 | uint64(val)
	case off == 0x0a4: // QueueUsedHigh
		q := &c.queues[c.queueSel]
		q.usedAddr = q.usedAddr&0xffffffff | uint64(val)<<32
	}
}

// ---------------- virtqueue helpers ------------------------------------------

func (c *Core) descAt(q *virtq, i uint16) (desc, error) {
	var d desc
	var buf [16]byte
	if err := c.mem.readAt(q.descAddr+uint64(i)*16, buf[:]); err != nil {
		return d, err
	}
	d.addr = binary.LittleEndian.Uint64(buf[0:])
	d.len = binary.LittleEndian.Uint32(buf[8:])
	d.flags = binary.LittleEndian.Uint16(buf[12:])
	d.next = binary.LittleEndian.Uint16(buf[14:])
	// A descriptor is guest-RAM-backed by definition: anything pointing
	// outside RAM is malformed, and consumers allocate make([]byte, d.len)
	// before touching the address, so the guest must not control host
	// allocation size either.
	if !c.mem.contains(d.addr, uint64(d.len)) {
		return desc{}, fmt.Errorf("descriptor @ %#x+%#x outside guest RAM", d.addr, d.len)
	}
	return d, nil
}

// availChain pops the next available descriptor chain.
// Returns head index and the flattened descriptor list.
func (c *Core) availChain(q *virtq) (uint16, []desc, bool) {
	if !q.numValid() {
		return 0, nil, false
	}
	var availIdx uint16
	var buf [4]byte
	if err := c.mem.readAt(q.availAddr, buf[:2]); err != nil {
		return 0, nil, false
	}
	if err := c.mem.readAt(q.availAddr+2, buf[2:4]); err != nil {
		return 0, nil, false
	}
	availIdx = binary.LittleEndian.Uint16(buf[2:4])
	if availIdx == q.lastAvail {
		return 0, nil, false
	}
	// one chain per notify iteration step
	var headBuf [2]byte
	if err := c.mem.readAt(q.availAddr+4+uint64(q.lastAvail%uint16(q.num))*2, headBuf[:]); err != nil {
		return 0, nil, false
	}
	head := binary.LittleEndian.Uint16(headBuf[:])
	q.lastAvail++

	var chain []desc
	var total uint64
	d, err := c.descAt(q, head)
	if err != nil {
		return 0, nil, false
	}
	for {
		chain = append(chain, d)
		total += uint64(d.len)
		// per-chain byte cap: ~65 max-length descriptors must not sum to
		// more than RAM (a legitimate chain never does)
		if total > c.mem.size() {
			return 0, nil, false
		}
		if d.flags&vringDescFNext == 0 {
			break
		}
		d, err = c.descAt(q, d.next)
		if err != nil || len(chain) > 64 {
			return 0, nil, false
		}
	}
	return head, chain, true
}

// pushUsedProbe is a test hook.
var pushUsedProbe func(q *virtq, head uint16, written uint32)

// pushUsed appends a used element and raises an interrupt.
func (c *Core) pushUsed(q *virtq, head uint16, written uint32) {
	if !q.numValid() {
		return
	}
	if pushUsedProbe != nil {
		pushUsedProbe(q, head, written)
	}
	var usedIdxBuf [2]byte
	if err := c.mem.readAt(q.usedAddr+2, usedIdxBuf[:]); err != nil {
		return
	}
	usedIdx := binary.LittleEndian.Uint16(usedIdxBuf[:])
	elem := make([]byte, 8)
	binary.LittleEndian.PutUint32(elem[0:], uint32(head))
	binary.LittleEndian.PutUint32(elem[4:], written)
	if err := c.mem.writeAt(q.usedAddr+4+uint64(usedIdx%uint16(q.num))*8, elem); err != nil {
		return
	}
	usedIdx++
	binary.LittleEndian.PutUint16(usedIdxBuf[:], usedIdx)
	if err := c.mem.writeAt(q.usedAddr+2, usedIdxBuf[:]); err != nil {
		return
	}
	if c.interruptSuppressed(q) {
		return
	}
	c.raiseIRQ(virtioIntUsedBuffer)
}

func (c *Core) raiseIRQ(bit uint32) {
	c.isr |= bit
	c.irqLine(c.irq, true) // trigger/pulse; guest EOI clears
}

// vringAvailFNoInterrupt is the avail-ring flags bit the driver sets to
// suppress used-buffer interrupts.
const vringAvailFNoInterrupt = 1

// pushUsed appends a used element and interrupts — unless the driver
// suppressed used-buffer notifications via the avail ring flags.
func (c *Core) interruptSuppressed(q *virtq) bool {
	var flags [2]byte
	if err := c.mem.readAt(q.availAddr, flags[:]); err != nil {
		return false
	}
	return flags[0]&vringAvailFNoInterrupt != 0
}

// splitChain splits a descriptor chain into (driver-readable, driver-writable)
// byte ranges — the classic request layout: header out, data in, status in.
func splitChain(chain []desc) (out, in []desc) {
	for i, d := range chain {
		if d.flags&vringDescFWrite != 0 {
			return chain[:i], chain[i:]
		}
	}
	return chain, nil
}

// readChains copies all "out" descriptors into one buffer.
func (c *Core) readChains(ds []desc) ([]byte, error) {
	var out []byte
	for _, d := range ds {
		buf := make([]byte, d.len)
		if err := c.mem.readAt(d.addr, buf); err != nil {
			return nil, err
		}
		out = append(out, buf...)
	}
	return out, nil
}

// writeChains scatters data into "in" descriptors; returns bytes written.
func (c *Core) writeChains(ds []desc, data []byte) (uint32, error) {
	var n uint32
	for _, d := range ds {
		if n >= uint32(len(data)) {
			break
		}
		chunk := data[n:]
		if uint32(len(chunk)) > d.len {
			chunk = chunk[:d.len]
		}
		if err := c.mem.writeAt(d.addr, chunk); err != nil {
			return n, err
		}
		n += uint32(len(chunk))
	}
	return n, nil
}

// FSTagLen is the virtio-fs tag length limit from the spec (defined here,
// not in vfs.go, so platforms without virtio-fs can still validate tags).
const FSTagLen = 36
