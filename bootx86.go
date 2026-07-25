package main

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
	x86MaxRAM       = 0xc0000000 // keep RAM below the virtio-mmio window

	x86MPSFloatingPtr = 0xf0000 // scanned by default_find_smp_config()
	x86MPSConfigTable = 0xf0100
)

// setupX86Boot writes boot_params, e820, the cmdline, identity-mapped page
// tables (4 GiB, 2 MiB pages), the GDT and the MPS table into guest RAM.
func setupX86Boot(ram []byte, cmdline string, memSize uint64, ncpus int) error {
	if memSize > x86MaxRAM {
		return fmt.Errorf("x86-64 backend supports up to %d MiB of RAM (device window at %#x); got %d MiB",
			x86MaxRAM>>20, x86MMIOBase, memSize>>20)
	}
	if len(cmdline)+1 > x86CmdlineMax {
		return fmt.Errorf("kernel cmdline too long (%d > %d)", len(cmdline), x86CmdlineMax)
	}
	if len(ram) < 0x100000 {
		return fmt.Errorf("guest RAM too small for x86 boot assets")
	}
	zp := ram[x86ZeroPage:]

	// --- struct boot_params / setup_header fields ---
	zp[0x1e8] = 2                                              // e820_entries
	binary.LittleEndian.PutUint16(zp[0x1fa:], 0xffff)          // vid_mode = normal
	binary.LittleEndian.PutUint16(zp[0x206:], 0x020d)          // header version 2.13
	zp[0x210] = 0xff                                           // type_of_loader = undefined bootloader
	zp[0x211] = 0x41                                           // loadflags = LOADED_HIGH|KEEP_SEGMENTS
	binary.LittleEndian.PutUint32(zp[0x214:], 0x100000)        // code32_start (conventional)
	binary.LittleEndian.PutUint32(zp[0x228:], x86CmdlineAddr)  // cmd_line_ptr
	binary.LittleEndian.PutUint32(zp[0x238:], x86CmdlineMax-1) // cmdline_size (protocol >= 2.06)
	// hardware_subarch (0x23c) = 0: PC

	// --- e820: [0, 0x9fc00) RAM, [0x100000, memSize) RAM ---
	putE820(zp[0x2d0:], 0, x86MemHoleStart, 1)
	putE820(zp[0x2d0+20:], x86MemHoleEnd, memSize-x86MemHoleEnd, 1)

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
// CPUs (SMP) and finds the IO-APIC. Layout follows kvmtool's mptable.c:
// NO ISA->IO-APIC interrupt entries.
func writeMPS(ram []byte, ncpus int) {
	if ncpus < 1 {
		ncpus = 1
	}
	ioapicID := byte(ncpus + 1) // kvmtool: ioapic id right after LAPIC ids

	// entry sizes: processor=20, bus=8, ioapic=8, int/lint=8.
	// Layout follows kvmtool's mptable.c: NO ISA->IO-APIC interrupt
	// entries. Legacy IRQs (<16) stay in virtual-wire PIC mode — KVM's
	// in-kernel irqchip asserts IRQs <16 to both the i8259 and the
	// IO-APIC, so drivers using legacy IRQs (virtio-mmio slots, UART)
	// get interrupts through the PIC without IO-APIC routing. An INT
	// entry for IRQ0 instead sends the kernel down the IO-APIC-timer
	// path where the timer IRQ is never allocated -> NULL deref in
	// check_timer(). Only LINT0 (ExtINT) and LINT1 (NMI) are declared.
	nEntries := ncpus + 2 + 1 + 2
	baseLen := 44 + ncpus*20 + 2*8 + 8 + 2*8

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
	p += 8

	// header checksum
	var sum byte
	for _, b := range ct[:baseLen] {
		sum += b
	}
	ct[7] = -sum
}

func putE820(b []byte, addr, size uint64, typ uint32) {
	binary.LittleEndian.PutUint64(b[0:], addr)
	binary.LittleEndian.PutUint64(b[8:], size)
	binary.LittleEndian.PutUint32(b[16:], typ)
}

// loadKernelX86 loads a vmlinux ELF64 (what sbx ships as
// nerdbox-kernel-x86_64) into guest RAM at each PT_LOAD's physical address
// and returns the ELF entry point.
func loadKernelX86(img []byte, ram []byte) (entry uint64, err error) {
	if len(img) < 64 || string(img[1:4]) != "ELF" {
		return 0, fmt.Errorf("not an ELF64 kernel")
	}
	if img[4] != 2 || img[5] != 1 { // ELFCLASS64, little-endian
		return 0, fmt.Errorf("kernel is not a 64-bit little-endian ELF")
	}
	if mach := binary.LittleEndian.Uint16(img[18:]); mach != 62 { // EM_X86_64
		return 0, fmt.Errorf("kernel ELF machine %d, want 62 (x86-64)", mach)
	}
	entry = binary.LittleEndian.Uint64(img[24:])
	phoff := binary.LittleEndian.Uint64(img[32:])
	phnum := int(binary.LittleEndian.Uint16(img[56:]))
	phentsize := int(binary.LittleEndian.Uint16(img[54:]))
	if phnum == 0 || phentsize < 56 {
		return 0, fmt.Errorf("kernel ELF has no usable program headers")
	}
	// Validate the header table before indexing (truncated/crafted files
	// must produce errors, not panics); all arithmetic is overflow-safe.
	if phoff >= uint64(len(img)) || uint64(phnum) > (uint64(len(img))-phoff)/uint64(phentsize) {
		return 0, fmt.Errorf("kernel ELF program headers outside file (phoff %#x, phnum %d, size %d)", phoff, phnum, len(img))
	}
	loaded := 0
	for i := 0; i < phnum; i++ {
		ph := img[phoff+uint64(i*phentsize):]
		if binary.LittleEndian.Uint32(ph[0:]) != 1 { // PT_LOAD
			continue
		}
		off := binary.LittleEndian.Uint64(ph[8:])
		paddr := binary.LittleEndian.Uint64(ph[24:])
		filesz := binary.LittleEndian.Uint64(ph[32:])
		memsz := binary.LittleEndian.Uint64(ph[40:])
		if off > uint64(len(img)) || filesz > uint64(len(img))-off {
			return 0, fmt.Errorf("kernel segment file range %#x+%#x outside file (%d bytes)", off, filesz, len(img))
		}
		if memsz < filesz {
			return 0, fmt.Errorf("kernel segment memsz %#x < filesz %#x", memsz, filesz)
		}
		if memsz > uint64(len(ram)) || paddr > uint64(len(ram))-memsz {
			return 0, fmt.Errorf("kernel segment @ %#x (%d bytes) exceeds guest RAM", paddr, memsz)
		}
		copy(ram[paddr:], img[off:off+filesz]) // memsz>filesz tail stays zero (BSS)
		loaded++
	}
	if loaded == 0 {
		return 0, fmt.Errorf("kernel ELF has no PT_LOAD segments")
	}
	fmt.Printf("kernel: %d ELF segments loaded, entry %#x\n", loaded, entry)
	return entry, nil
}
