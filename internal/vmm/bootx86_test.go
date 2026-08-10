package vmm

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

type countingReaderAt struct {
	reader io.ReaderAt
	bytes  int
}

func (r *countingReaderAt) ReadAt(dst []byte, offset int64) (int, error) {
	n, err := r.reader.ReadAt(dst, offset)
	r.bytes += n
	return n, err
}

func TestSetupX86BootZeroPage(t *testing.T) {
	ram := make([]byte, 16<<20)
	cmd := "console=ttyS0 root=/dev/vda ro nokaslr -- -vsock-cid=3"
	if err := setupX86Boot(ram, cmd, 1024<<20, 4); err != nil {
		t.Fatal(err)
	}
	zp := ram[x86ZeroPage:]
	if got := zp[0x1e8]; got != 2 {
		t.Errorf("e820_entries = %d, want 2", got)
	}
	if got := binary.LittleEndian.Uint16(zp[0x206:]); got != 0x020d {
		t.Errorf("hdr.version = %#x", got)
	}
	if zp[0x210] != 0xff {
		t.Errorf("type_of_loader = %#x", zp[0x210])
	}
	if got := binary.LittleEndian.Uint32(zp[0x228:]); got != x86CmdlineAddr {
		t.Errorf("cmd_line_ptr = %#x", got)
	}
	// e820 entry 0: [0, 0x9fc00) RAM
	if a := binary.LittleEndian.Uint64(zp[0x2d0:]); a != 0 {
		t.Errorf("e820[0].addr = %#x", a)
	}
	if s := binary.LittleEndian.Uint64(zp[0x2d8:]); s != x86MemHoleStart {
		t.Errorf("e820[0].size = %#x", s)
	}
	if typ := binary.LittleEndian.Uint32(zp[0x2e0:]); typ != 1 {
		t.Errorf("e820[0].type = %d", typ)
	}
	// e820 entry 1: [0x100000, 1G) RAM
	if a := binary.LittleEndian.Uint64(zp[0x2d0+20:]); a != x86MemHoleEnd {
		t.Errorf("e820[1].addr = %#x", a)
	}
	if s := binary.LittleEndian.Uint64(zp[0x2d0+28:]); s != (1024<<20)-x86MemHoleEnd {
		t.Errorf("e820[1].size = %#x", s)
	}
	// cmdline copied + NUL-terminated
	if string(ram[x86CmdlineAddr:x86CmdlineAddr+len(cmd)]) != cmd {
		t.Errorf("cmdline not at %#x", x86CmdlineAddr)
	}
	if ram[x86CmdlineAddr+len(cmd)] != 0 {
		t.Error("cmdline not NUL-terminated")
	}
}

func TestSetupX86BootPageTables(t *testing.T) {
	ram := make([]byte, 16<<20)
	if err := setupX86Boot(ram, "x", 512<<20, 1); err != nil {
		t.Fatal(err)
	}
	// walk: PML4[0] -> PDPT[i] -> PD[j] -> 2MiB page at phys
	pml4e := binary.LittleEndian.Uint64(ram[x86PML4:])
	if pml4e != x86PDPT|0x3 {
		t.Fatalf("PML4[0] = %#x", pml4e)
	}
	for _, phys := range []uint64{0, 0x200000, 0x40000000, 0xc0000000, 0xffe00000} {
		i := phys >> 30         // PDPT slot (1 GiB each)
		j := (phys >> 21) & 511 // PD slot (2 MiB each)
		pdpte := binary.LittleEndian.Uint64(ram[x86PDPT+i*8:])
		pdAddr := pdpte &^ 0x3
		pde := binary.LittleEndian.Uint64(ram[pdAddr+j*8:])
		if pde != phys|0x83 {
			t.Errorf("walk(%#x): PDE = %#x, want %#x", phys, pde, phys|0x83)
		}
	}
	// GDT: code64 @0x10, data @0x18
	if g := binary.LittleEndian.Uint64(ram[x86GDT+0x10:]); g != 0x00AF9B000000FFFF {
		t.Errorf("GDT code64 = %#x", g)
	}
	if g := binary.LittleEndian.Uint64(ram[x86GDT+0x18:]); g != 0x00CF93000000FFFF {
		t.Errorf("GDT data = %#x", g)
	}
}

func TestSetupX86BootMPS(t *testing.T) {
	ram := make([]byte, 16<<20)
	if err := setupX86Boot(ram, "x", 512<<20, 4); err != nil {
		t.Fatal(err)
	}
	fp := ram[x86MPSFloatingPtr:]
	if string(fp[:4]) != "_MP_" {
		t.Fatal("no _MP_ signature")
	}
	if addr := binary.LittleEndian.Uint32(fp[4:]); addr != x86MPSConfigTable {
		t.Fatalf("MP_ ptr = %#x", addr)
	}
	var sum byte
	for _, b := range fp[:16] {
		sum += b
	}
	if sum != 0 {
		t.Error("floating pointer checksum != 0")
	}
	ct := ram[x86MPSConfigTable:]
	if string(ct[:4]) != "PCMP" {
		t.Fatal("no PCMP signature")
	}
	baseLen := int(binary.LittleEndian.Uint16(ct[4:]))
	sum = 0
	for _, b := range ct[:baseLen] {
		sum += b
	}
	if sum != 0 {
		t.Error("config table checksum != 0")
	}
	if n := binary.LittleEndian.Uint16(ct[34:]); int(n) != 4+2+1+2 {
		t.Errorf("entry count = %d", n)
	}
	if lapic := binary.LittleEndian.Uint32(ct[36:]); lapic != 0xfee00000 {
		t.Errorf("LAPIC addr = %#x", lapic)
	}
	// processor entries: 4 cpus, cpu0 = BSP, all enabled
	for i := 0; i < 4; i++ {
		e := ct[44+i*20:]
		if e[0] != 0 || e[1] != byte(i) {
			t.Errorf("cpu%d entry: type=%d id=%d", i, e[0], e[1])
		}
		if e[3]&1 == 0 {
			t.Errorf("cpu%d not enabled", i)
		}
		wantBSP := i == 0
		if (e[3]&2 != 0) != wantBSP {
			t.Errorf("cpu%d BSP flag wrong", i)
		}
	}
	// kvmtool layout: PCI bus 0, ISA bus 1, ioapic id 5, then 2 LINT
	// entries (ExtINT on LINT0, NMI on LINT1) and NO ISA INT entries.
	p := 44 + 4*20
	if ct[p] != 1 || ct[p+1] != 0 || string(ct[p+2:p+8]) != "PCI   " {
		t.Errorf("PCI bus entry: %+v", ct[p:p+8])
	}
	p += 8
	if ct[p] != 1 || ct[p+1] != 1 || string(ct[p+2:p+8]) != "ISA   " {
		t.Errorf("ISA bus entry: %+v", ct[p:p+8])
	}
	p += 8
	if ct[p] != 2 || ct[p+1] != 5 || binary.LittleEndian.Uint32(ct[p+4:]) != 0xfec00000 {
		t.Errorf("ioapic entry: %+v", ct[p:p+8])
	}
	p += 8
	if ct[p] != 4 || ct[p+1] != 3 || ct[p+6] != 0 || ct[p+7] != 0 {
		t.Errorf("LINT0 entry: %+v", ct[p:p+8])
	}
	p += 8
	if ct[p] != 4 || ct[p+1] != 4 || ct[p+6] != 0 || ct[p+7] != 1 {
		t.Errorf("LINT1 entry: %+v", ct[p:p+8])
	}
}

func TestLoadKernelX86(t *testing.T) {
	ram := make([]byte, 64<<20)
	// build a minimal ELF64 with one PT_LOAD: entry 0x27176b0, paddr 0x1000000
	img := make([]byte, 0x3000)
	copy(img[0:], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(img[16:], 2)  // ET_EXEC
	binary.LittleEndian.PutUint16(img[18:], 62) // EM_X86_64
	binary.LittleEndian.PutUint64(img[24:], 0x27176b0)
	binary.LittleEndian.PutUint64(img[32:], 0x1000) // phoff
	binary.LittleEndian.PutUint16(img[54:], 56)     // phentsize
	binary.LittleEndian.PutUint16(img[56:], 1)      // phnum
	ph := img[0x1000:]
	binary.LittleEndian.PutUint32(ph[0:], 1)          // PT_LOAD
	binary.LittleEndian.PutUint64(ph[8:], 0x2000)     // offset
	binary.LittleEndian.PutUint64(ph[24:], 0x1000000) // paddr
	binary.LittleEndian.PutUint64(ph[32:], 0x100)     // filesz
	binary.LittleEndian.PutUint64(ph[40:], 0x180)     // memsz (bss tail)
	for i := 0; i < 0x100; i++ {
		img[0x2000+i] = 0xab
	}
	reader := &countingReaderAt{reader: bytes.NewReader(img)}
	entry, err := loadKernelX86(reader, uint64(len(img)), ram)
	if err != nil {
		t.Fatal(err)
	}
	if entry != 0x27176b0 {
		t.Errorf("entry = %#x", entry)
	}
	if ram[0x1000000] != 0xab || ram[0x10000ff] != 0xab {
		t.Error("segment not copied")
	}
	if ram[0x1000100] != 0 {
		t.Error("bss tail not zero")
	}
	const wantRead = 64 + 56 + 0x100
	if reader.bytes != wantRead {
		t.Fatalf("loader read %d bytes, want %d; it must not buffer the whole kernel", reader.bytes, wantRead)
	}
}

func TestInsertKernelArgs(t *testing.T) {
	got := insertKernelArgs("console=ttyS0 ro -- -vsock-cid=3", "virtio_mmio.device=0x1000@0xc0000000:3")
	want := "console=ttyS0 ro virtio_mmio.device=0x1000@0xc0000000:3 -- -vsock-cid=3"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if got := insertKernelArgs("console=ttyS0", "a=b"); got != "console=ttyS0 a=b" {
		t.Errorf("no-separator case: %q", got)
	}
}
