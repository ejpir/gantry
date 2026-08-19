//go:build (linux && amd64) || windows

package devices

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

type MMIOOp struct {
	IsWrite bool
	Width   int    // access width in bytes (1,2,4,8)
	Imm     uint64 // write immediate (C6/C7)
	ImmOK   bool
	Reg     int // destination (read) / source (write) GPR index, -1 if imm
	SignExt bool
	Dest64  bool // destination register is 64-bit (REX.W)
	Length  int  // total instruction length in bytes
}

func DecodeMMIO(ins []byte) (MMIOOp, error) {
	op := MMIOOp{Reg: -1}
	i := 0
	var rex, rexW, rexR byte
	osz16 := false
	// prefixes
	for i < len(ins) {
		b := ins[i]
		switch {
		case b == 0x66:
			osz16 = true
		case b >= 0x40 && b <= 0x4f:
			rex = b
			rexW, rexR = (b>>3)&1, (b>>2)&1
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
		op.IsWrite = true
		op.Width = 4
		if b == 0x88 {
			op.Width = 1
		} else if osz16 {
			op.Width = 2
		} else if rexW == 1 {
			op.Width = 8
		}
	case 0x8a, 0x8b: // mov r/m -> reg
		op.Width = 4
		if b == 0x8a {
			op.Width = 1
		} else if osz16 {
			op.Width = 2
		} else if rexW == 1 {
			op.Width = 8
		}
		op.Dest64 = rexW == 1
	case 0xc6, 0xc7: // mov imm -> r/m, /0
		op.IsWrite = true
		op.ImmOK = true
		op.Width = 4
		if b == 0xc6 {
			op.Width = 1
		} else if rexW == 1 {
			// REX.W + C7 /0 stores the sign-extended imm32 to r/m64. REX.W
			// takes precedence over a 66H prefix, so this comes first.
			op.Width = 8
		} else if osz16 {
			op.Width = 2
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
				op.Width = 1
			} else {
				op.Width = 2
			}
			op.SignExt = b2 >= 0xbe
			op.Dest64 = rexW == 1
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
	if op.ImmOK {
		n := op.Width
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
		if b == 0xc7 && op.Width == 8 && v&0x80000000 != 0 {
			v |= 0xffffffff00000000 // sign-extended imm32
		}
		op.Imm = v
		i += n
	} else {
		op.Reg = modrmReg // src/dest GPR (REX.R already folded)
	}
	op.Length = i
	return op, nil
}

// ApplyMMIO executes a decoded op against the device: reads fetch a value
// and zero/sign-extend it into the destination register; writes fetch the
// source value (register or immediate).
func ApplyMMIO(op MMIOOp,
	getReg func(idx int) uint64, setReg func(idx int, v uint64),
	devRead func(width int) uint64, devWrite func(width int, val uint64)) {

	if op.IsWrite {
		var v uint64
		if op.ImmOK {
			v = op.Imm
		} else {
			v = getReg(op.Reg)
		}
		if op.Width < 8 {
			v &= (uint64(1) << (8 * op.Width)) - 1
		}
		devWrite(op.Width, v)
		return
	}
	v := devRead(op.Width)
	var out uint64
	switch {
	case op.SignExt:
		switch op.Width {
		case 1:
			out = uint64(int64(int8(v)))
		case 2:
			out = uint64(int64(int16(v)))
		default:
			out = uint64(int64(int32(v)))
		}
	case op.Dest64:
		out = v
	default: // 32-bit destination zeroes the upper half (x86-64 semantics)
		out = uint64(uint32(v))
	}
	setReg(op.Reg, out)
}
