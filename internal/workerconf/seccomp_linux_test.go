package workerconf

import (
	"testing"

	"golang.org/x/sys/unix"
)

func runFilter(t *testing.T, program []unix.SockFilter, nr uint32, args ...uint64) uint32 {
	t.Helper()
	valueAt := func(offset uint32) uint32 {
		switch offset {
		case offNr:
			return nr
		case offArch:
			return auditArch
		}
		if offset < offArg0 || offset >= offArg0+6*8 {
			t.Fatalf("unsupported seccomp_data offset %d", offset)
		}
		arg := int((offset - offArg0) / 8)
		if arg >= len(args) {
			return 0
		}
		if (offset-offArg0)%8 == 4 {
			return uint32(args[arg] >> 32)
		}
		return uint32(args[arg])
	}

	var accumulator uint32
	for pc := 0; pc < len(program); {
		instruction := program[pc]
		switch instruction.Code {
		case bpfLD | bpfW | bpfABS:
			accumulator = valueAt(instruction.K)
			pc++
		case bpfALU | bpfAND | bpfK:
			accumulator &= instruction.K
			pc++
		case bpfJMP | bpfJEQ | bpfK:
			if accumulator == instruction.K {
				pc += int(instruction.Jt) + 1
			} else {
				pc += int(instruction.Jf) + 1
			}
		case bpfJMP | bpfJGE | bpfK:
			if accumulator >= instruction.K {
				pc += int(instruction.Jt) + 1
			} else {
				pc += int(instruction.Jf) + 1
			}
		case bpfJMP | bpfJGT | bpfK:
			if accumulator > instruction.K {
				pc += int(instruction.Jt) + 1
			} else {
				pc += int(instruction.Jf) + 1
			}
		case bpfRET | bpfK:
			return instruction.K
		default:
			t.Fatalf("unsupported BPF instruction %#x at %d", instruction.Code, pc)
		}
	}
	t.Fatal("seccomp filter fell off the program")
	return 0
}

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
			block := i + 1 + int(ins.Jt)
			if block+1 >= len(prog) || prog[block].Code != bpfLD|bpfW|bpfABS || prog[block].K != offArg0 {
				t.Fatalf("sched_getaffinity check does not load args[0] after dispatch at %d", i)
			}
			if prog[block+1].Code != bpfJMP|bpfJEQ|bpfK || prog[block+1].K != 0 {
				t.Fatalf("sched_getaffinity check does not compare pid zero after dispatch at %d", i)
			}
		case uint32(unix.SYS_TGKILL):
			sawTGKill = true
			block := i + 1 + int(ins.Jt)
			if block+1 >= len(prog) || prog[block].Code != bpfLD|bpfW|bpfABS || prog[block].K != offArg0 {
				t.Fatalf("tgkill check does not load args[0] after dispatch at %d", i)
			}
			if prog[block+1].Code != bpfJMP|bpfJEQ|bpfK || prog[block+1].K != selfTGID {
				t.Fatalf("tgkill check does not compare the self TGID after dispatch at %d", i)
			}
		case uint32(unix.SYS_FCNTL):
			sawFcntl = true
			block := i + 1 + int(ins.Jt)
			if block+len(safeFcntlCommands) >= len(prog) ||
				prog[block].Code != bpfLD|bpfW|bpfABS || prog[block].K != offArg1 {
				t.Fatalf("fcntl check does not load args[1] after dispatch at %d", i)
			}
			for j, cmd := range safeFcntlCommands {
				got := prog[block+1+j]
				if got.Code != bpfJMP|bpfJEQ|bpfK || got.K != cmd {
					t.Fatalf("fcntl safe command %d = %#x/%d, want JEQ/%d", j, got.Code, got.K, cmd)
				}
			}
		case uint32(sysIoctlNr()):
			sawIOCTL = true
			block := i + 1 + int(ins.Jt)
			// The ioctl argument check must read the REQUEST (args[1]),
			// never the fd (args[0]) — the AL2023 KVM regression.
			if block >= len(prog) || prog[block].Code != bpfLD|bpfW|bpfABS || prog[block].K != offArg1 {
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

func TestRoleFiltersEnforceCapabilities(t *testing.T) {
	const selfTGID = uint32(1234)
	network := buildFilterFor(NetworkSpec(4, ""), selfTGID)
	vmm := buildFilter(selfTGID)

	for name, test := range map[string]struct {
		nr   uint32
		args []uint64
	}{
		"IPv4 TCP": {unix.SYS_SOCKET, []uint64{unix.AF_INET, unix.SOCK_STREAM | unix.SOCK_CLOEXEC, 0}},
		"IPv6 UDP": {unix.SYS_SOCKET, []uint64{unix.AF_INET6, unix.SOCK_DGRAM | unix.SOCK_NONBLOCK, unix.IPPROTO_UDP}},
		"connect":  {unix.SYS_CONNECT, nil},
		"accept4":  {unix.SYS_ACCEPT4, nil},
		"read config": {unix.SYS_OPENAT, []uint64{
			0, 0, unix.O_RDONLY | unix.O_CLOEXEC,
		}},
	} {
		t.Run("network allows "+name, func(t *testing.T) {
			if got := runFilter(t, network, test.nr, test.args...); got != retAllow {
				t.Fatalf("result %#x, want allow", got)
			}
		})
	}

	for name, test := range map[string]struct {
		nr   uint32
		args []uint64
	}{
		"Unix socket":   {unix.SYS_SOCKET, []uint64{unix.AF_UNIX, unix.SOCK_STREAM, 0}},
		"raw socket":    {unix.SYS_SOCKET, []uint64{unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP}},
		"packet socket": {unix.SYS_SOCKET, []uint64{unix.AF_PACKET, unix.SOCK_DGRAM, 0}},
		"write config":  {unix.SYS_OPENAT, []uint64{0, 0, unix.O_WRONLY | unix.O_CREAT | unix.O_CLOEXEC}},
		"KVM ioctl":     {unix.SYS_IOCTL, []uint64{9, 0xAE01}},
		"SCM receive":   {unix.SYS_RECVMSG, nil},
		"SCM send":      {unix.SYS_SENDMSG, nil},
	} {
		t.Run("network denies "+name, func(t *testing.T) {
			if got := runFilter(t, network, test.nr, test.args...); got != retErrno|sysEPERM {
				t.Fatalf("result %#x, want EPERM", got)
			}
		})
	}

	if got := runFilter(t, vmm, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, 0); got != retErrno|sysEPERM {
		t.Fatalf("VMM socket result %#x, want EPERM", got)
	}
	if got := runFilter(t, vmm, unix.SYS_IOCTL, 9, 0xAE01); got != retAllow {
		t.Fatalf("VMM KVM ioctl result %#x, want allow", got)
	}
	if got := runFilter(t, network, unix.SYS_CLONE3); got != retErrno|sysENOSYS {
		t.Fatalf("clone3 result %#x, want ENOSYS", got)
	}
	if got := runFilter(t, network, unix.SYS_CLONE, uint64(unix.SIGCHLD)); got != retErrno|sysEPERM {
		t.Fatalf("process clone result %#x, want EPERM", got)
	}
	threadFlags := uint64(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD)
	if got := runFilter(t, network, unix.SYS_CLONE, threadFlags); got != retAllow {
		t.Fatalf("thread clone result %#x, want allow", got)
	}
	if got := runFilter(t, network, unix.SYS_PRLIMIT64, 0, unix.RLIMIT_NPROC, 0, 1); got != retAllow {
		t.Fatalf("self RLIMIT_NPROC query result %#x, want allow", got)
	}
	for name, args := range map[string][]uint64{
		"outside pid": {1, unix.RLIMIT_NPROC, 0, 1},
		"new limit":   {0, unix.RLIMIT_NPROC, 1, 0},
		"other limit": {0, unix.RLIMIT_NOFILE, 0, 1},
	} {
		t.Run("prlimit denies "+name, func(t *testing.T) {
			if got := runFilter(t, network, unix.SYS_PRLIMIT64, args...); got != retErrno|sysEPERM {
				t.Fatalf("result %#x, want EPERM", got)
			}
		})
	}
}

func TestMCPProfileUsesOnlyInheritedRelayDescriptors(t *testing.T) {
	const selfTGID = uint32(1234)
	mcp := buildFilterFor(MCPSpec(5, ""), selfTGID)
	for name, test := range map[string]struct {
		nr   uint32
		args []uint64
	}{
		"SCM receive": {unix.SYS_RECVMSG, nil},
		"SCM send":    {unix.SYS_SENDMSG, nil},
		"IPv4 socket": {unix.SYS_SOCKET, []uint64{unix.AF_INET, unix.SOCK_STREAM, 0}},
		"connect":     {unix.SYS_CONNECT, nil},
		"path open":   {unix.SYS_OPENAT, []uint64{0, 0, unix.O_RDONLY}},
		"KVM ioctl":   {unix.SYS_IOCTL, []uint64{9, 0xAE01}},
		"exec":        {unix.SYS_EXECVE, nil},
	} {
		t.Run("denies "+name, func(t *testing.T) {
			if got := runFilter(t, mcp, test.nr, test.args...); got != retErrno|sysEPERM {
				t.Fatalf("result %#x, want EPERM", got)
			}
		})
	}
}

func TestUnknownSyscallProfilePanicsClosed(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("unknown syscall profile did not panic")
		}
	}()
	_ = buildFilterFor(Spec{Profile: SyscallProfile(255)}, 1234)
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

func TestVMMWhitelistHasNoFileShapeOrLockMutation(t *testing.T) {
	allowed := make(map[uint32]bool, len(whitelist)+len(archWhitelist()))
	for _, nr := range append(append([]uint32(nil), whitelist...), archWhitelist()...) {
		allowed[nr] = true
	}
	for name, nr := range map[string]uint32{
		"ftruncate": unix.SYS_FTRUNCATE,
		"fallocate": unix.SYS_FALLOCATE,
		"flock":     unix.SYS_FLOCK,
	} {
		if allowed[nr] {
			t.Errorf("%s remains in the VMM seccomp whitelist", name)
		}
		if got := runFilter(t, buildFilter(1234), nr); got != retErrno|sysEPERM {
			t.Errorf("%s filter result %#x, want EPERM", name, got)
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
