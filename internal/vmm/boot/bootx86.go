package boot

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
	"strings"
)

const (
	ZeroPage    = 0x7000
	GDT         = 0x8000
	StackTop    = 0x7000 // rsp starts at 0x6ff0 (below the zero page)
	PML4        = 0xa000
	pdpt        = 0xb000
	pd          = 0xc000 // 4 consecutive pages
	CmdlineAddr = 0x20000
	cmdlineMax  = 0x2000

	memHoleStart = 0x9fc00    // end of usable low memory
	memHoleEnd   = 0x100000   // kernel load base / end of ISA hole
	LowRAMEnd    = 0xc0000000 // 3 GiB: start of the virtio/platform MMIO hole
	HighRAMStart = 0x100000000

	virtioMemBootSize  = 512 << 20
	VirtioMemBlockSize = 128 << 20

	MPSFloatingPtr = 0xf0000 // scanned by default_find_smp_config()
	mpsConfigTable = 0xf0100
)

// RAMRegion maps one contiguous part of the host RAM allocation into the PC
// guest-physical layout, recording both its guest address and host offset. RAM
// above 3 GiB is relocated above the traditional 3-4 GiB MMIO hole while
// remaining contiguous in the host allocation.
type RAMRegion struct {
	GuestBase  uint64
	HostOffset uint64
	Size       uint64
}

func RAMRegions(memSize uint64) []RAMRegion {
	return RAMRegionsWithLow(memSize, min(memSize, uint64(LowRAMEnd)))
}

func RAMRegionsWithLow(memSize, lowSize uint64) []RAMRegion {
	lowSize = min(lowSize, memSize)
	regions := []RAMRegion{{Size: lowSize}}
	if memSize > lowSize {
		regions = append(regions, RAMRegion{
			GuestBase: HighRAMStart, HostOffset: lowSize, Size: memSize - lowSize,
		})
	}
	return regions
}

// VirtioMemLayout keeps enough ordinary e820 RAM for the kernel and early
// userspace, while aligning the hot-added tail to x86's 128 MiB memory-block
// granularity. Windows uses this layout by default; other hosts retain their
// demand-paged direct mappings unless explicitly enabled for validation.
func VirtioMemLayout(hostOS string, memSize uint64, setting string) (bootSize uint64, enabled bool) {
	switch strings.ToLower(strings.TrimSpace(setting)) {
	case "1", "true", "yes", "on":
	case "0", "false", "no", "off":
		return memSize, false
	case "":
		if hostOS != "windows" {
			return memSize, false
		}
	default:
		return memSize, false
	}
	if memSize <= virtioMemBootSize {
		return memSize, false
	}
	bootSize = virtioMemBootSize + memSize%VirtioMemBlockSize
	if bootSize >= memSize || bootSize > LowRAMEnd {
		return memSize, false
	}
	return bootSize, true
}

// SetupX86 writes boot_params, e820, the cmdline, identity-mapped page
// tables (4 GiB, 2 MiB pages), the GDT and the MPS table into guest RAM.
func SetupX86(ram []byte, cmdline string, memSize uint64, ncpus int) error {
	if len(cmdline)+1 > cmdlineMax {
		return fmt.Errorf("kernel cmdline too long (%d > %d)", len(cmdline), cmdlineMax)
	}
	if len(ram) < 0x100000 {
		return fmt.Errorf("guest RAM too small for x86 boot assets")
	}
	zp := ram[ZeroPage:]

	// --- struct boot_params / setup_header fields ---
	e820Entries := byte(2)
	lowSize := memSize
	if memSize > LowRAMEnd {
		e820Entries = 3
		lowSize = LowRAMEnd
	}
	zp[0x1e8] = e820Entries                                 // e820_entries
	binary.LittleEndian.PutUint16(zp[0x1fa:], 0xffff)       // vid_mode = normal
	binary.LittleEndian.PutUint16(zp[0x206:], 0x020d)       // header version 2.13
	zp[0x210] = 0xff                                        // type_of_loader = undefined bootloader
	zp[0x211] = 0x41                                        // loadflags = LOADED_HIGH|KEEP_SEGMENTS
	binary.LittleEndian.PutUint32(zp[0x214:], 0x100000)     // code32_start (conventional)
	binary.LittleEndian.PutUint32(zp[0x228:], CmdlineAddr)  // cmd_line_ptr
	binary.LittleEndian.PutUint32(zp[0x238:], cmdlineMax-1) // cmdline_size (protocol >= 2.06)
	// hardware_subarch (0x23c) = 0: PC

	// --- e820: low RAM around the ISA hole; optional high RAM above 4 GiB ---
	putE820(zp[0x2d0:], 0, memHoleStart, 1)
	putE820(zp[0x2d0+20:], memHoleEnd, lowSize-memHoleEnd, 1)
	if e820Entries == 3 {
		putE820(zp[0x2d0+40:], HighRAMStart, memSize-LowRAMEnd, 1)
	}

	// --- cmdline ---
	copy(ram[CmdlineAddr:], cmdline)
	ram[CmdlineAddr+len(cmdline)] = 0

	// --- page tables: identity map 4 GiB with 2 MiB pages ---
	const presentRW = 0x3
	binary.LittleEndian.PutUint64(ram[PML4:], pdpt|presentRW)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(ram[pdpt+i*8:], uint64(pd+i*0x1000)|presentRW)
		for j := 0; j < 512; j++ {
			phys := uint64(i*512+j) << 21
			binary.LittleEndian.PutUint64(ram[pd+i*0x1000+j*8:], phys|0x83) // PS|P|RW
		}
	}

	// --- GDT: null, code64 (L=1) @ 0x10, data @ 0x18 ---
	binary.LittleEndian.PutUint64(ram[GDT+0x10:], 0x00AF9B000000FFFF) // 64-bit code, DPL0
	binary.LittleEndian.PutUint64(ram[GDT+0x18:], 0x00CF93000000FFFF) // data, DPL0

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
	fp := ram[MPSFloatingPtr:]
	copy(fp[0:], "_MP_")
	binary.LittleEndian.PutUint32(fp[4:], mpsConfigTable)
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
	ct := ram[mpsConfigTable:]
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
		e[7] = byte(ISAIRQGSI(irq))
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

// ISAIRQGSI returns the IO-APIC input advertised for an ISA interrupt.
// The PC architecture routes the PIT's ISA IRQ0 to IO-APIC input 2; input 0
// is not the timer route once the MPS table publishes explicit assignments.
// KVM applies this override in its in-kernel routing table. Userspace irqchips
// (WHPX) must apply the same translation before raising their input line.
func ISAIRQGSI(irq int) int {
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

// LoadKernelX86 loads a vmlinux ELF64 (what the reference stack ships as
// nerdbox-kernel-x86_64) into guest RAM at each PT_LOAD's physical address
// and returns the ELF entry point.
func LoadKernelX86(image io.ReaderAt, imageSize uint64, ram []byte) (entry uint64, err error) {
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
