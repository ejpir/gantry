package vmm

// Minimal x86-64 instruction decoder for MMIO emulation. WHPX MemoryAccess
// exits provide the faulting instruction bytes but not the operand value —
// unlike KVM — so for writes we decode the source register/immediate, and
// for reads the destination register. Only the mov-family that Linux
// generates for device MMIO is supported:
//
//	88/89/8A/8B   mov r/m <-> reg (8/16/32/64)
//	C6/C7 /0      mov imm -> r/m
//	0F B6/B7      movzx r/m8,r/m16 -> reg
//	0F BE/BF      movsx r/m8,r/m16 -> reg
//
// with REX and 0x66 prefixes and full ModRM/SIB/displacement length decode.

import "fmt"

type x86MMIOOp struct {
	isWrite bool
	width   int    // access width in bytes (1,2,4,8)
	imm     uint64 // write immediate (C6/C7)
	immOK   bool
	reg     int // destination (read) / source (write) GPR index, -1 if imm
	signExt bool
	dest64  bool // destination register is 64-bit (REX.W)
	length  int  // total instruction length in bytes
}

func decodeX86MMIO(ins []byte) (x86MMIOOp, error) {
	op := x86MMIOOp{reg: -1}
	i := 0
	var rex, rexW, rexR, rexB byte
	osz16 := false
	// prefixes
	for i < len(ins) {
		b := ins[i]
		switch {
		case b == 0x66:
			osz16 = true
		case b >= 0x40 && b <= 0x4f:
			rex = b
			rexW, rexR, rexB = (b>>3)&1, (b>>2)&1, b&1
		case b == 0xf0 || b == 0xf2 || b == 0xf3 ||
			b == 0x26 || b == 0x2e || b == 0x36 || b == 0x3e || b == 0x64 || b == 0x65:
			// lock/rep/segment overrides: irrelevant for MMIO
		default:
			goto opcode
		}
		i++
	}
opcode:
	if i >= len(ins) {
		return op, fmt.Errorf("truncated instruction")
	}
	_ = rex
	b := ins[i]
	i++
	var modrmReg int // /r field (extended), also used as /digit for C6/C7
	switch b {
	case 0x88, 0x89: // mov reg -> r/m
		op.isWrite = true
		op.width = 4
		if b == 0x88 {
			op.width = 1
		} else if osz16 {
			op.width = 2
		} else if rexW == 1 {
			op.width = 8
		}
	case 0x8a, 0x8b: // mov r/m -> reg
		op.width = 4
		if b == 0x8a {
			op.width = 1
		} else if osz16 {
			op.width = 2
		} else if rexW == 1 {
			op.width = 8
		}
		op.dest64 = rexW == 1
	case 0xc6, 0xc7: // mov imm -> r/m, /0
		op.isWrite = true
		op.immOK = true
		op.width = 4
		if b == 0xc6 {
			op.width = 1
		} else if osz16 {
			op.width = 2
		}
	case 0x0f:
		if i >= len(ins) {
			return op, fmt.Errorf("truncated 0f instruction")
		}
		b2 := ins[i]
		i++
		switch b2 {
		case 0xb6, 0xb7, 0xbe, 0xbf: // movzx/movsx r/m -> reg
			if b2 == 0xb6 || b2 == 0xbe {
				op.width = 1
			} else {
				op.width = 2
			}
			op.signExt = b2 >= 0xbe
			op.dest64 = rexW == 1
		default:
			return op, fmt.Errorf("unsupported 0f opcode %#x", b2)
		}
	default:
		return op, fmt.Errorf("unsupported opcode %#x", b)
	}

	// ModRM (+SIB, +disp)
	if i >= len(ins) {
		return op, fmt.Errorf("truncated modrm")
	}
	m := ins[i]
	i++
	mod := m >> 6
	modrmReg = int((m>>3)&7) | int(rexR)<<3
	rm := m & 7
	if (b == 0xc6 || b == 0xc7) && modrmReg&7 != 0 {
		return op, fmt.Errorf("mov imm with /%d not supported", modrmReg&7)
	}
	if mod == 3 {
		return op, fmt.Errorf("register-direct, not MMIO")
	}
	if rm == 4 { // SIB
		if i >= len(ins) {
			return op, fmt.Errorf("truncated sib")
		}
		sib := ins[i]
		i++
		if mod == 0 && sib&7 == 5 { // disp32 base
			i += 4
		}
	} else if mod == 0 && rm == 5 { // RIP + disp32
		i += 4
	}
	switch mod {
	case 1:
		i++ // disp8
	case 2:
		i += 4 // disp32
	}
	if i > len(ins) {
		return op, fmt.Errorf("truncated displacement")
	}

	// immediate for C6/C7
	if op.immOK {
		n := op.width
		if n == 8 {
			n = 4 // C7 imm is 32-bit sign-extended
		}
		if i+n > len(ins) {
			return op, fmt.Errorf("truncated immediate")
		}
		var v uint64
		for j := 0; j < n; j++ {
			v |= uint64(ins[i+j]) << (8 * j)
		}
		if b == 0xc7 && op.width == 8 && v&0x80000000 != 0 {
			v |= 0xffffffff00000000 // sign-extended imm32
		}
		op.imm = v
		i += n
	} else {
		op.reg = modrmReg | int(rexB&0) // src/dest GPR (REX.R already folded)
	}
	op.length = i
	return op, nil
}

// applyX86MMIO executes a decoded op against the device: reads fetch a value
// and zero/sign-extend it into the destination register; writes fetch the
// source value (register or immediate).
func applyX86MMIO(op x86MMIOOp,
	getReg func(idx int) uint64, setReg func(idx int, v uint64),
	devRead func(width int) uint64, devWrite func(width int, val uint64)) {

	if op.isWrite {
		var v uint64
		if op.immOK {
			v = op.imm
		} else {
			v = getReg(op.reg)
		}
		if op.width < 8 {
			v &= (uint64(1) << (8 * op.width)) - 1
		}
		devWrite(op.width, v)
		return
	}
	v := devRead(op.width)
	var out uint64
	switch {
	case op.signExt:
		switch op.width {
		case 1:
			out = uint64(int64(int8(v)))
		case 2:
			out = uint64(int64(int16(v)))
		default:
			out = uint64(int64(int32(v)))
		}
	case op.dest64:
		out = v
	default: // 32-bit destination zeroes the upper half (x86-64 semantics)
		out = uint64(uint32(v))
	}
	setReg(op.reg, out)
}
