package vmm

// x86-64 guest boot assets: the "64-bit boot protocol" from
// Documentation/arch/x86/boot.rst, as used by QEMU when it loads a vmlinux
// ELF (which is what Docker ships as nerdbox-kernel-x86_64):
//
//   - the kernel's PT_LOAD segments are copied to their physical addresses;
//   - the VMM enters at e_entry in long mode with paging enabled (identity
//     map), a flat 64-bit code segment, and rsi -> struct boot_params
//     ("zero page") carrying the cmdline and e820 memory map.
//
// Everything lives in the first 64 KiB of guest RAM (the legacy ISA hole is
// above us at 0x9fc00..0x100000):
//
//	0x6000  initial stack (grows down)
//	0x7000  zero page (struct boot_params)
//	0x8000  GDT (null, code64 @0x10, data @0x18)
//	0xa000  PML4 -> 0xb000 PDPT -> 0xc000.. PD[0..3] (identity map 4 GiB)
//	0x20000 kernel cmdline (NUL-terminated)

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	x86ZeroPage    = 0x7000
	x86GDT         = 0x8000
	x86StackTop    = 0x7000 // rsp starts at 0x6ff0 (below the zero page)
	x86PML4        = 0xa000
	x86PDPT        = 0xb000
	x86PD          = 0xc000 // 4 consecutive pages
	x86CmdlineAddr = 0x20000
	x86CmdlineMax  = 0x2000

	x86MemHoleStart = 0x9fc00    // end of usable low memory
	x86MemHoleEnd   = 0x100000   // kernel load base / end of ISA hole
	x86LowRAMEnd    = 0xc0000000 // 3 GiB: start of the virtio/platform MMIO hole
	x86HighRAMStart = 0x100000000

	x86MPSFloatingPtr = 0xf0000 // scanned by default_find_smp_config()
	x86MPSConfigTable = 0xf0100
)

// x86RAMRegion maps one contiguous part of the host RAM allocation into the
// PC guest-physical layout. RAM above 3 GiB is relocated above the traditional
// 3-4 GiB MMIO hole while remaining contiguous in the host allocation.
type x86RAMRegion struct {
	guestBase  uint64
	hostOffset uint64
	size       uint64
}

func x86RAMRegions(memSize uint64) []x86RAMRegion {
	lowSize := min(memSize, uint64(x86LowRAMEnd))
	regions := []x86RAMRegion{{size: lowSize}}
	if memSize > lowSize {
		regions = append(regions, x86RAMRegion{
			guestBase: x86HighRAMStart, hostOffset: lowSize, size: memSize - lowSize,
		})
	}
	return regions
}

// setupX86Boot writes boot_params, e820, the cmdline, identity-mapped page
// tables (4 GiB, 2 MiB pages), the GDT and the MPS table into guest RAM.
func setupX86Boot(ram []byte, cmdline string, memSize uint64, ncpus int) error {
	if len(cmdline)+1 > x86CmdlineMax {
		return fmt.Errorf("kernel cmdline too long (%d > %d)", len(cmdline), x86CmdlineMax)
	}
	if len(ram) < 0x100000 {
		return fmt.Errorf("guest RAM too small for x86 boot assets")
	}
	zp := ram[x86ZeroPage:]

	// --- struct boot_params / setup_header fields ---
	e820Entries := byte(2)
	lowSize := memSize
	if memSize > x86LowRAMEnd {
		e820Entries = 3
		lowSize = x86LowRAMEnd
	}
	zp[0x1e8] = e820Entries                                    // e820_entries
	binary.LittleEndian.PutUint16(zp[0x1fa:], 0xffff)          // vid_mode = normal
	binary.LittleEndian.PutUint16(zp[0x206:], 0x020d)          // header version 2.13
	zp[0x210] = 0xff                                           // type_of_loader = undefined bootloader
	zp[0x211] = 0x41                                           // loadflags = LOADED_HIGH|KEEP_SEGMENTS
	binary.LittleEndian.PutUint32(zp[0x214:], 0x100000)        // code32_start (conventional)
	binary.LittleEndian.PutUint32(zp[0x228:], x86CmdlineAddr)  // cmd_line_ptr
	binary.LittleEndian.PutUint32(zp[0x238:], x86CmdlineMax-1) // cmdline_size (protocol >= 2.06)
	// hardware_subarch (0x23c) = 0: PC

	// --- e820: low RAM around the ISA hole; optional high RAM above 4 GiB ---
	putE820(zp[0x2d0:], 0, x86MemHoleStart, 1)
	putE820(zp[0x2d0+20:], x86MemHoleEnd, lowSize-x86MemHoleEnd, 1)
	if e820Entries == 3 {
		putE820(zp[0x2d0+40:], x86HighRAMStart, memSize-x86LowRAMEnd, 1)
	}

	// --- cmdline ---
	copy(ram[x86CmdlineAddr:], cmdline)
	ram[x86CmdlineAddr+len(cmdline)] = 0

	// --- page tables: identity map 4 GiB with 2 MiB pages ---
	const presentRW = 0x3
	binary.LittleEndian.PutUint64(ram[x86PML4:], x86PDPT|presentRW)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(ram[x86PDPT+i*8:], uint64(x86PD+i*0x1000)|presentRW)
		for j := 0; j < 512; j++ {
			phys := uint64(i*512+j) << 21
			binary.LittleEndian.PutUint64(ram[x86PD+i*0x1000+j*8:], phys|0x83) // PS|P|RW
		}
	}

	// --- GDT: null, code64 (L=1) @ 0x10, data @ 0x18 ---
	binary.LittleEndian.PutUint64(ram[x86GDT+0x10:], 0x00AF9B000000FFFF) // 64-bit code, DPL0
	binary.LittleEndian.PutUint64(ram[x86GDT+0x18:], 0x00CF93000000FFFF) // data, DPL0

	writeMPS(ram, ncpus)
	return nil
}

// writeMPS installs an Intel MultiProcessor Specification v1.4 floating
// pointer + config table. Without ACPI this is how the kernel enumerates
// CPUs (SMP), the IO-APIC, and the ISA interrupt routes Gantry exposes.
func writeMPS(ram []byte, ncpus int) {
	if ncpus < 1 {
		ncpus = 1
	}
	ioapicID := byte(ncpus + 1) // kvmtool: ioapic id right after LAPIC ids

	// entry sizes: processor=20, bus=8, ioapic=8, int/lint=8. Publish
	// every connected ISA route rather than making Linux synthesize a
	// default table and report a firmware bug. IRQ0 uses the conventional
	// IO-APIC pin 2; IRQ2 is the legacy PIC cascade and is not routable.
	const isaRoutes = 15
	nEntries := ncpus + 2 + 1 + isaRoutes + 2
	baseLen := 44 + ncpus*20 + 2*8 + 8 + isaRoutes*8 + 2*8

	// --- floating pointer structure (16 bytes) ---
	fp := ram[x86MPSFloatingPtr:]
	copy(fp[0:], "_MP_")
	binary.LittleEndian.PutUint32(fp[4:], x86MPSConfigTable)
	fp[8] = 1 // length = 16 bytes
	fp[9] = 4 // spec rev 1.4
	var fpsum byte
	for i, b := range fp[:16] {
		if i != 10 {
			fpsum += b
		}
	}
	fp[10] = -fpsum // checksum
	// fp[11] = default config 0 (config table present); fp[12:16] reserved

	// --- config table header (44 bytes) ---
	ct := ram[x86MPSConfigTable:]
	copy(ct[0:], "PCMP")
	binary.LittleEndian.PutUint16(ct[4:], uint16(baseLen))
	ct[6] = 4                     // spec rev 1.4
	copy(ct[8:], "GANTRY  ")      // OEM ID (8)
	copy(ct[16:], "NERDBOX VM  ") // product ID (exactly 12 bytes)
	// @28 OEM table ptr = 0, @32 OEM table size = 0
	binary.LittleEndian.PutUint16(ct[34:], uint16(nEntries))
	binary.LittleEndian.PutUint32(ct[36:], 0xfee00000) // LAPIC address
	// @40 extended table length = 0, @42 extended checksum = 0
	p := 44

	// --- processor entries ---
	for i := 0; i < ncpus; i++ {
		e := ct[p:]
		e[0] = 0       // entry type: processor
		e[1] = byte(i) // local APIC id = vCPU id (KVM convention)
		e[2] = 0x14    // local APIC version
		e[3] = 0x01    // enabled
		if i == 0 {
			e[3] |= 0x02 // BSP
		}
		binary.LittleEndian.PutUint32(e[4:], 0x600)      // signature
		binary.LittleEndian.PutUint32(e[8:], 0x0383fbff) // feature flags
		p += 20
	}

	// --- PCI bus entry (kept for kvmtool parity; no devices use it) ---
	e := ct[p:]
	e[0] = 1 // entry type: bus
	e[1] = 0 // bus id
	copy(e[2:], "PCI   ")
	p += 8

	// --- ISA bus entry ---
	e = ct[p:]
	e[0] = 1 // entry type: bus
	e[1] = 1 // bus id
	copy(e[2:], "ISA   ")
	p += 8

	// --- I/O APIC entry ---
	e = ct[p:]
	e[0] = 2 // entry type: I/O APIC
	e[1] = ioapicID
	e[2] = 0x11 // version (matches KVM's in-kernel 82093AA)
	e[3] = 1    // enabled
	binary.LittleEndian.PutUint32(e[4:], 0xfec00000)
	p += 8

	// --- ISA IRQ sources -> IO-APIC ---
	for irq := 0; irq < 16; irq++ {
		if irq == 2 {
			continue
		}
		e = ct[p:]
		e[0] = 3 // entry type: interrupt source
		e[1] = 0 // interrupt type: INT
		binary.LittleEndian.PutUint16(e[2:], 0)
		e[4] = 1 // source bus id 1 (ISA)
		e[5] = byte(irq)
		e[6] = ioapicID
		e[7] = byte(isaIRQGSI(irq))
		p += 8
	}

	// --- LINT0: ISA IRQ0 -> BSP LAPIC LINT0 as ExtINT (virtual wire) ---
	e = ct[p:]
	e[0] = 4                                // entry type: local interrupt
	e[1] = 3                                // interrupt type: ExtINT
	binary.LittleEndian.PutUint16(e[2:], 0) // po/trig: bus default
	e[4] = 1                                // source bus id 1 (ISA)
	e[5] = 0                                // source bus IRQ 0
	e[6] = 0                                // dest: LAPIC id 0 (BSP)
	e[7] = 0                                // dest LINT pin 0
	p += 8

	// --- LINT1: ISA -> BSP LAPIC LINT1 as NMI ---
	e = ct[p:]
	e[0] = 4 // entry type: local interrupt
	e[1] = 4 // interrupt type: NMI
	binary.LittleEndian.PutUint16(e[2:], 0)
	e[4] = 1 // source bus id 1 (ISA)
	e[5] = 0
	e[6] = 0 // dest: LAPIC id 0 (BSP)
	e[7] = 1 // dest LINT pin 1

	// header checksum
	var sum byte
	for _, b := range ct[:baseLen] {
		sum += b
	}
	ct[7] = -sum
}

// isaIRQGSI returns the IO-APIC input advertised for an ISA interrupt.
// The PC architecture routes the PIT's ISA IRQ0 to IO-APIC input 2; input 0
// is not the timer route once the MPS table publishes explicit assignments.
// KVM applies this override in its in-kernel routing table. Userspace irqchips
// (WHPX) must apply the same translation before raising their input line.
func isaIRQGSI(irq int) int {
	if irq == 0 {
		return 2
	}
	return irq
}

func putE820(b []byte, addr, size uint64, typ uint32) {
	binary.LittleEndian.PutUint64(b[0:], addr)
	binary.LittleEndian.PutUint64(b[8:], size)
	binary.LittleEndian.PutUint32(b[16:], typ)
}

// loadKernelX86 loads a vmlinux ELF64 (what the reference stack ships as
// nerdbox-kernel-x86_64) into guest RAM at each PT_LOAD's physical address
// and returns the ELF entry point.
func loadKernelX86(image io.ReaderAt, imageSize uint64, ram []byte) (entry uint64, err error) {
	if imageSize < 64 {
		return 0, fmt.Errorf("not an ELF64 kernel")
	}
	var header [64]byte
	if err := readAtExact(image, header[:], 0); err != nil {
		return 0, fmt.Errorf("read ELF header: %w", err)
	}
	if header[0] != 0x7f || string(header[1:4]) != "ELF" {
		return 0, fmt.Errorf("not an ELF64 kernel")
	}
	if header[4] != 2 || header[5] != 1 { // ELFCLASS64, little-endian
		return 0, fmt.Errorf("kernel is not a 64-bit little-endian ELF")
	}
	if mach := binary.LittleEndian.Uint16(header[18:]); mach != 62 { // EM_X86_64
		return 0, fmt.Errorf("kernel ELF machine %d, want 62 (x86-64)", mach)
	}
	entry = binary.LittleEndian.Uint64(header[24:])
	phoff := binary.LittleEndian.Uint64(header[32:])
	phnum := uint64(binary.LittleEndian.Uint16(header[56:]))
	phentsize := uint64(binary.LittleEndian.Uint16(header[54:]))
	if phnum == 0 || phentsize < 56 {
		return 0, fmt.Errorf("kernel ELF has no usable program headers")
	}
	if phoff > imageSize || phnum > (imageSize-phoff)/phentsize {
		return 0, fmt.Errorf("kernel ELF program headers outside file (phoff %#x, phnum %d, size %d)", phoff, phnum, imageSize)
	}
	loaded := 0
	var ph [56]byte
	for i := uint64(0); i < phnum; i++ {
		offset := phoff + i*phentsize
		if err := readAtExact(image, ph[:], offset); err != nil {
			return 0, fmt.Errorf("read kernel program header %d: %w", i, err)
		}
		if binary.LittleEndian.Uint32(ph[0:]) != 1 { // PT_LOAD
			continue
		}
		off := binary.LittleEndian.Uint64(ph[8:])
		paddr := binary.LittleEndian.Uint64(ph[24:])
		filesz := binary.LittleEndian.Uint64(ph[32:])
		memsz := binary.LittleEndian.Uint64(ph[40:])
		if off > imageSize || filesz > imageSize-off {
			return 0, fmt.Errorf("kernel segment file range %#x+%#x outside file (%d bytes)", off, filesz, imageSize)
		}
		if memsz < filesz {
			return 0, fmt.Errorf("kernel segment memsz %#x < filesz %#x", memsz, filesz)
		}
		if memsz > uint64(len(ram)) || paddr > uint64(len(ram))-memsz {
			return 0, fmt.Errorf("kernel segment @ %#x (%d bytes) exceeds guest RAM", paddr, memsz)
		}
		if err := readAtExact(image, ram[paddr:paddr+filesz], off); err != nil {
			return 0, fmt.Errorf("read kernel segment %d: %w", i, err)
		}
		loaded++
	}
	if loaded == 0 {
		return 0, fmt.Errorf("kernel ELF has no PT_LOAD segments")
	}
	fmt.Printf("kernel: %d ELF segments loaded, entry %#x\n", loaded, entry)
	return entry, nil
}

// readAtExact avoids a SectionReader allocation on the kernel startup path.
// ReaderAt permits an implementation to return an error together with a full
// buffer, so the byte count is authoritative here.
func readAtExact(r io.ReaderAt, dst []byte, offset uint64) error {
	if len(dst) == 0 {
		return nil
	}
	n, err := r.ReadAt(dst, int64(offset))
	if n == len(dst) {
		return nil
	}
	if err != nil {
		return err
	}
	return io.ErrUnexpectedEOF
}
