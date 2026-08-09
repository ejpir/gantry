package workerconf

import (
	"testing"

	"golang.org/x/sys/unix"
)

func sysIoctlNr() int { return unix.SYS_IOCTL }

// TestBuildFilterOffsets validates the assembled BPF program
// structurally: every jump must land on an instruction inside the
// program and the last instruction must be a RET. An out-of-bounds
// jump makes the kernel reject the whole filter with EINVAL (this
// happened once with an off-by-one in the ioctl block).
func TestBuildFilterOffsets(t *testing.T) {
	const selfTGID = uint32(1234)
	prog := buildFilter(selfTGID)
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
	var sawAffinity, sawTGKill, sawFcntl, sawIOCTL bool
	for i, ins := range prog {
		if ins.Code != bpfJMP|bpfJEQ|bpfK {
			continue
		}
		switch ins.K {
		case uint32(unix.SYS_SCHED_GETAFFINITY):
			sawAffinity = true
			if i+2 >= len(prog) || prog[i+1].Code != bpfLD|bpfW|bpfABS || prog[i+1].K != offArg0 {
				t.Fatalf("sched_getaffinity check does not load args[0] after dispatch at %d", i)
			}
			if prog[i+2].Code != bpfJMP|bpfJEQ|bpfK || prog[i+2].K != 0 {
				t.Fatalf("sched_getaffinity check does not compare pid zero after dispatch at %d", i)
			}
		case uint32(unix.SYS_TGKILL):
			sawTGKill = true
			if i+2 >= len(prog) || prog[i+1].Code != bpfLD|bpfW|bpfABS || prog[i+1].K != offArg0 {
				t.Fatalf("tgkill check does not load args[0] after dispatch at %d", i)
			}
			if prog[i+2].Code != bpfJMP|bpfJEQ|bpfK || prog[i+2].K != selfTGID {
				t.Fatalf("tgkill check does not compare the self TGID after dispatch at %d", i)
			}
		case uint32(unix.SYS_FCNTL):
			sawFcntl = true
			if i+1+len(safeFcntlCommands) >= len(prog) ||
				prog[i+1].Code != bpfLD|bpfW|bpfABS || prog[i+1].K != offArg1 {
				t.Fatalf("fcntl check does not load args[1] after dispatch at %d", i)
			}
			for j, cmd := range safeFcntlCommands {
				got := prog[i+2+j]
				if got.Code != bpfJMP|bpfJEQ|bpfK || got.K != cmd {
					t.Fatalf("fcntl safe command %d = %#x/%d, want JEQ/%d", j, got.Code, got.K, cmd)
				}
			}
		case uint32(sysIoctlNr()):
			sawIOCTL = true
			// The ioctl argument check must read the REQUEST (args[1]),
			// never the fd (args[0]) — the AL2023 KVM regression.
			if i+1 >= len(prog) || prog[i+1].Code != bpfLD|bpfW|bpfABS || prog[i+1].K != 24 {
				t.Fatalf("ioctl arg check does not load args[1] (offset 24) after dispatch at %d", i)
			}
		}
	}
	if !sawAffinity {
		t.Error("no SYS_SCHED_GETAFFINITY dispatch in filter")
	}
	if !sawTGKill {
		t.Error("no SYS_TGKILL dispatch in filter")
	}
	if !sawFcntl {
		t.Error("no SYS_FCNTL dispatch in filter")
	}
	if !sawIOCTL {
		t.Error("no SYS_IOCTL dispatch in filter")
	}
}

func TestFcntlSignalCommandsExcluded(t *testing.T) {
	allowed := make(map[uint32]bool, len(safeFcntlCommands))
	for _, cmd := range safeFcntlCommands {
		allowed[cmd] = true
	}
	for name, cmd := range map[string]uint32{
		"F_SETOWN":    unix.F_SETOWN,
		"F_SETOWN_EX": unix.F_SETOWN_EX,
		"F_SETSIG":    unix.F_SETSIG,
	} {
		if allowed[cmd] {
			t.Errorf("%s remains in the fcntl command allowlist", name)
		}
	}
}

func TestVMMWhitelistHasNoPathAuthority(t *testing.T) {
	allowed := make(map[uint32]bool, len(whitelist)+len(archWhitelist()))
	for _, nr := range append(append([]uint32(nil), whitelist...), archWhitelist()...) {
		allowed[nr] = true
	}
	for name, nr := range map[string]uint32{
		"openat":     unix.SYS_OPENAT,
		"openat2":    unix.SYS_OPENAT2,
		"newfstatat": unix.SYS_NEWFSTATAT,
		"faccessat2": unix.SYS_FACCESSAT2,
		"readlinkat": unix.SYS_READLINKAT,
		"renameat2":  unix.SYS_RENAMEAT2,
		"unlinkat":   unix.SYS_UNLINKAT,
		"mkdirat":    unix.SYS_MKDIRAT,
		"mknodat":    unix.SYS_MKNODAT,
	} {
		if allowed[nr] {
			t.Errorf("%s remains in the VMM seccomp whitelist", name)
		}
	}
}

func TestVMMWhitelistHasNoCrossProcessAuthority(t *testing.T) {
	allowed := make(map[uint32]bool, len(whitelist)+len(archWhitelist()))
	for _, nr := range append(append([]uint32(nil), whitelist...), archWhitelist()...) {
		allowed[nr] = true
	}
	for name, nr := range map[string]uint32{
		"kill":                 unix.SYS_KILL,
		"tkill":                unix.SYS_TKILL,
		"tgkill":               unix.SYS_TGKILL,
		"rt_sigqueueinfo":      unix.SYS_RT_SIGQUEUEINFO,
		"rt_tgsigqueueinfo":    unix.SYS_RT_TGSIGQUEUEINFO,
		"pidfd_send_signal":    unix.SYS_PIDFD_SEND_SIGNAL,
		"pidfd_open":           unix.SYS_PIDFD_OPEN,
		"pidfd_getfd":          unix.SYS_PIDFD_GETFD,
		"process_vm_readv":     unix.SYS_PROCESS_VM_READV,
		"process_vm_writev":    unix.SYS_PROCESS_VM_WRITEV,
		"ptrace":               unix.SYS_PTRACE,
		"sched_getaffinity":    unix.SYS_SCHED_GETAFFINITY,
		"sched_setaffinity":    unix.SYS_SCHED_SETAFFINITY,
		"get_robust_list":      unix.SYS_GET_ROBUST_LIST,
		"membarrier":           unix.SYS_MEMBARRIER,
		"fcntl (unrestricted)": unix.SYS_FCNTL,
	} {
		if allowed[nr] {
			t.Errorf("%s remains in the generic VMM seccomp whitelist", name)
		}
	}
}
