//go:build (linux && amd64) || windows

package vmm

import "testing"

func TestDecodeX86MMIO(t *testing.T) {
	cases := []struct {
		name string
		ins  []byte
		want x86MMIOOp
	}{
		{"movl (%rax),%ecx", []byte{0x8b, 0x08}, x86MMIOOp{width: 4, reg: 1, length: 2}},
		{"movl %ecx,(%rax)", []byte{0x89, 0x08}, x86MMIOOp{isWrite: true, width: 4, reg: 1, length: 2}},
		{"movb %cl,(%rax)", []byte{0x88, 0x08}, x86MMIOOp{isWrite: true, width: 1, reg: 1, length: 2}},
		{"movb (%rax),%cl", []byte{0x8a, 0x08}, x86MMIOOp{width: 1, reg: 1, length: 2}},
		{"movw %cx,(%rax)", []byte{0x66, 0x89, 0x08}, x86MMIOOp{isWrite: true, width: 2, reg: 1, length: 3}},
		{"movq %rcx,(%rax)", []byte{0x48, 0x89, 0x08}, x86MMIOOp{isWrite: true, width: 8, reg: 1, length: 3}},
		{"movq (%rax),%rcx", []byte{0x48, 0x8b, 0x08}, x86MMIOOp{width: 8, reg: 1, length: 3, dest64: true}},
		{"movzbl (%rax),%ecx", []byte{0x0f, 0xb6, 0x08}, x86MMIOOp{width: 1, reg: 1, length: 3}},
		{"movzwl (%rax),%ecx", []byte{0x0f, 0xb7, 0x08}, x86MMIOOp{width: 2, reg: 1, length: 3}},
		{"movsbq (%rax),%rcx", []byte{0x48, 0x0f, 0xbe, 0x08}, x86MMIOOp{width: 1, reg: 1, length: 4, signExt: true, dest64: true}},
		{"movl $1,(%rax)", []byte{0xc7, 0x00, 0x01, 0x00, 0x00, 0x00}, x86MMIOOp{isWrite: true, width: 4, immOK: true, imm: 1, reg: -1, length: 6}},
		{"movb $0xff,(%rax)", []byte{0xc6, 0x00, 0xff}, x86MMIOOp{isWrite: true, width: 1, immOK: true, imm: 0xff, reg: -1, length: 3}},
		{"movl %ecx,0x10(%rax)", []byte{0x89, 0x48, 0x10}, x86MMIOOp{isWrite: true, width: 4, reg: 1, length: 3}},
		{"movl %ecx,0x1234(%rax)", []byte{0x89, 0x88, 0x34, 0x12, 0x00, 0x00}, x86MMIOOp{isWrite: true, width: 4, reg: 1, length: 6}},
		{"movl %ecx,(%rsp)", []byte{0x89, 0x0c, 0x24}, x86MMIOOp{isWrite: true, width: 4, reg: 1, length: 3}},
		{"movl %ecx,0x8(%rsp)", []byte{0x89, 0x4c, 0x24, 0x08}, x86MMIOOp{isWrite: true, width: 4, reg: 1, length: 4}},
		{"movl %ecx,(%rip)", []byte{0x89, 0x0d, 0x00, 0x00, 0x00, 0x00}, x86MMIOOp{isWrite: true, width: 4, reg: 1, length: 6}},
		{"movl %r9d,(%r10)", []byte{0x45, 0x89, 0x0a}, x86MMIOOp{isWrite: true, width: 4, reg: 9, length: 3}},
		{"movl (%r10),%r9d", []byte{0x45, 0x8b, 0x0a}, x86MMIOOp{width: 4, reg: 9, length: 3}},
		{"movl %ecx,(%r8)", []byte{0x41, 0x89, 0x08}, x86MMIOOp{isWrite: true, width: 4, reg: 1, length: 3}},
		{"movl %ecx,(,%rax,4)+disp32base5", []byte{0x89, 0x0c, 0x85, 0x00, 0x01, 0x00, 0x00}, x86MMIOOp{isWrite: true, width: 4, reg: 1, length: 7}},
	}
	for _, c := range cases {
		got, err := decodeX86MMIO(c.ins)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}
}

func TestApplyX86MMIORead(t *testing.T) {
	var regs [16]uint64
	get := func(i int) uint64 { return regs[i] }
	set := func(i int, v uint64) { regs[i] = v }
	devRead := func(w int) uint64 {
		if w != 4 {
			t.Errorf("width = %d", w)
		}
		return 0xdeadbeef
	}
	op, err := decodeX86MMIO([]byte{0x8b, 0x08}) // movl (%rax),%ecx
	if err != nil {
		t.Fatal(err)
	}
	regs[1] = 0xffffffffffffffff
	applyX86MMIO(op, get, set, devRead, func(int, uint64) {})
	if regs[1] != 0xdeadbeef {
		t.Errorf("ecx = %#x (upper 32 must be zeroed)", regs[1])
	}

	// movsbq: sign-extend byte into 64-bit reg
	op, _ = decodeX86MMIO([]byte{0x48, 0x0f, 0xbe, 0x08})
	applyX86MMIO(op, get, set, func(int) uint64 { return 0x80 }, func(int, uint64) {})
	if regs[1] != 0xffffffffffffff80 {
		t.Errorf("movsbq result = %#x", regs[1])
	}
}

func TestApplyX86MMIOWrite(t *testing.T) {
	var regs [16]uint64
	get := func(i int) uint64 { return regs[i] }
	set := func(i int, v uint64) { regs[i] = v }
	var gotW int
	var gotV uint64
	devWrite := func(w int, v uint64) { gotW, gotV = w, v }

	regs[1] = 0x1234567890
	op, _ := decodeX86MMIO([]byte{0x89, 0x08}) // movl %ecx,(%rax)
	applyX86MMIO(op, get, set, func(int) uint64 { return 0 }, devWrite)
	if gotW != 4 || gotV != 0x34567890 {
		t.Errorf("write: w=%d v=%#x", gotW, gotV)
	}

	op, _ = decodeX86MMIO([]byte{0xc7, 0x00, 0xef, 0xbe, 0xad, 0xde}) // movl $0xdeadbeef,(%rax)
	applyX86MMIO(op, get, set, func(int) uint64 { return 0 }, devWrite)
	if gotW != 4 || gotV != 0xdeadbeef {
		t.Errorf("imm write: w=%d v=%#x", gotW, gotV)
	}
}
