package workerconf

import "testing"

// TestBuildFilterOffsets validates the assembled BPF program
// structurally: every jump must land on an instruction inside the
// program and the last instruction must be a RET. An out-of-bounds
// jump makes the kernel reject the whole filter with EINVAL (this
// happened once with an off-by-one in the ioctl block).
func TestBuildFilterOffsets(t *testing.T) {
	prog := buildFilter()
	if len(prog) == 0 || len(prog) > 4096 {
		t.Fatalf("program length %d", len(prog))
	}
	last := prog[len(prog)-1]
	if last.Code != bpfRET|bpfK {
		t.Fatalf("last instruction is not a RET: %#x", last.Code)
	}
	for i, ins := range prog {
		isJump := ins.Code&0x05 == 0x05 // BPF_JMP class
		if !isJump {
			continue
		}
		for _, off := range []int{int(ins.Jt), int(ins.Jf)} {
			target := i + 1 + off
			if target < 0 || target >= len(prog) {
				t.Fatalf("instruction %d jumps out of bounds to %d (program %d)", i, target, len(prog))
			}
		}
	}
}
