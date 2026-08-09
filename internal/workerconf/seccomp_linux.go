package workerconf

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

var errDebugSkipped = errors.New("WORKERCONF_NOSECCOMP=1: filter skipped (debug)")

// Hand-rolled seccomp-bpf whitelist (no libseccomp cgo dependency — the
// list is small and static). Design notes:
//
//   - pathname-opening and *at mutation syscalls are absent. Share roots
//     stay in the trusted supervisor behind the request relay, so the VMM
//     has no legitimate path operation after Apply. This also prevents an
//     accidentally delegated directory fd from becoming a filesystem escape.
//   - socket/connect/bind/listen/accept are absent: the worker's data
//     plane is inherited descriptors only (net-dial probe gets EPERM).
//   - execve/execveat are absent: fork-only children inherit the same
//     namespaces and filter and cannot escape or do useful work.
//   - clone/clone3 are allowed UNMASKED: the Go runtime spawns threads
//     lazily after Apply, and clone3's flags live behind a pointer that
//     seccomp cannot dereference. execve is the real boundary.
//   - tgkill is allowed only when its thread-group argument is this
//     process. The Go runtime uses tgkill(getpid(), tid, sig), while an
//     unrestricted rule would let a namespace-less auto-mode worker signal
//     any same-UID host process.
//   - sched_getaffinity is allowed only for pid 0 (the calling thread), which
//     is the form used by the Go runtime. Arbitrary PID probes would otherwise
//     expose host-process existence in namespace-less auto mode.
//   - fcntl is command-filtered. Descriptor duplication/status operations are
//     needed by net.FileConn, but F_SETOWN/F_SETOWN_EX/F_SETSIG would provide
//     an alternate cross-process signal path through O_ASYNC sockets.
//   - ioctl is argument-filtered to the KVM command range
//     ((cmd & 0xFFFF) in [0xAE00, 0xAEFF]); KVM ioctls use type 0xAE
//     with nr 0x00-0xFF, direction/size bits masked off.
const (
	bpfLD                = 0x00
	bpfW                 = 0x00
	bpfABS               = 0x20
	bpfJMP               = 0x05
	bpfJEQ               = 0x10
	bpfJGT               = 0x20
	bpfJGE               = 0x30
	bpfK                 = 0x00
	bpfRET               = 0x06
	bpfALU               = 0x04
	bpfAND               = 0x50
	retKill              = 0x80000000
	retErrno             = 0x00050000
	retAllow             = 0x7fff0000
	sysEPERM             = 1
	seccompSetModeFilter = 1
	seccompFlagTSYNC     = 1
	offArch              = 4  // seccomp_data.arch
	offNr                = 0  // seccomp_data.nr
	offArg0              = 16 // low 32 bits of seccomp_data.args[0]
	offArg1              = 24 // low 32 bits of seccomp_data.args[1]
)

// whitelist is the syscall set a VMM worker needs post-Apply: the Go
// runtime (threads, GC, netpoll, timers), descriptor I/O on inherited
// fds and the KVM ioctl range (filtered separately). Names resolve per-arch
// via x/sys; the arch files add their arch-only runtime entries.
var whitelist = []uint32{
	unix.SYS_READ, unix.SYS_WRITE, unix.SYS_READV, unix.SYS_WRITEV,
	unix.SYS_PREAD64, unix.SYS_PWRITE64, unix.SYS_CLOSE, unix.SYS_DUP,
	unix.SYS_DUP3, unix.SYS_LSEEK,
	unix.SYS_MMAP, unix.SYS_MPROTECT, unix.SYS_MUNMAP, unix.SYS_MADVISE,
	unix.SYS_MREMAP, unix.SYS_BRK,
	unix.SYS_FUTEX, unix.SYS_SCHED_YIELD, unix.SYS_NANOSLEEP,
	unix.SYS_CLOCK_NANOSLEEP, unix.SYS_CLOCK_GETTIME,
	unix.SYS_GETPID, unix.SYS_GETTID,
	unix.SYS_RT_SIGACTION, unix.SYS_RT_SIGPROCMASK, unix.SYS_RT_SIGRETURN,
	unix.SYS_SIGALTSTACK,
	unix.SYS_EPOLL_CREATE1, unix.SYS_EPOLL_CTL, unix.SYS_EPOLL_PWAIT,
	unix.SYS_PPOLL, unix.SYS_PSELECT6, unix.SYS_EVENTFD2,
	unix.SYS_GETRANDOM, unix.SYS_RSEQ,
	unix.SYS_SET_ROBUST_LIST, unix.SYS_SET_TID_ADDRESS,
	unix.SYS_EXIT, unix.SYS_EXIT_GROUP,
	unix.SYS_CLONE, unix.SYS_CLONE3,
	unix.SYS_FSTAT, unix.SYS_FSTATFS,
	unix.SYS_FALLOCATE,
	unix.SYS_FSYNC, unix.SYS_FDATASYNC, unix.SYS_FLOCK,
	unix.SYS_FTRUNCATE,
	unix.SYS_RECVMSG, unix.SYS_SENDMSG, unix.SYS_SHUTDOWN,
	unix.SYS_GETSOCKNAME, unix.SYS_GETPEERNAME,
	// getsockopt/setsockopt are fd-scoped: net.FileConn probes SO_TYPE
	// on every descriptor it wraps (the vsock.forward path wraps each
	// guest-brokered socket post-Apply — the AL2023 RST regression).
	// They cannot create connectivity (socket/connect stay denied).
	unix.SYS_GETSOCKOPT, unix.SYS_SETSOCKOPT,
	unix.SYS_GETUID, unix.SYS_GETEUID, unix.SYS_GETGID, unix.SYS_GETEGID,
}

// safeFcntlCommands are descriptor-local operations used by the Go runtime,
// os.File, and net.FileConn after confinement. In particular, ownership and
// signal-selection commands are absent.
var safeFcntlCommands = []uint32{
	unix.F_DUPFD,
	unix.F_GETFD,
	unix.F_SETFD,
	unix.F_GETFL,
	unix.F_SETFL,
	unix.F_DUPFD_CLOEXEC,
}

func stmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: 0, Jf: 0, K: k}
}

func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// buildFilter assembles the BPF program. Jump targets are computed from
// final label positions so the jeq chain length is free to grow.
func buildFilter(selfTGID uint32) []unix.SockFilter {
	allowNrs := append(append([]uint32{}, whitelist...), archWhitelist()...)
	prog := make([]unix.SockFilter, 0, len(allowNrs)+20+len(safeFcntlCommands))
	// 0: arch check — a foreign-arch process image gets killed outright.
	prog = append(prog, stmt(bpfLD|bpfW|bpfABS, offArch))
	prog = append(prog, jump(bpfJMP|bpfJEQ|bpfK, auditArch, 1, 0))
	prog = append(prog, stmt(bpfRET|bpfK, retKill))
	// 3: nr dispatch.
	prog = append(prog, stmt(bpfLD|bpfW|bpfABS, offNr))
	dispatch := len(prog)
	// Reserve the jeq chain; jump offsets need ALLOW's final index.
	affinityBlock := dispatch + len(allowNrs)
	tgkillBlock := affinityBlock + 3 // JEQ, LD arg0, JEQ pid zero
	fcntlBlock := tgkillBlock + 3    // JEQ, LD arg0, JEQ selfTGID
	ioctlBlock := fcntlBlock + 2 + len(safeFcntlCommands)
	allowIdx := ioctlBlock + 5 // LD,AND,JGE,JGT + JEQ head = 5 instrs
	denyIdx := allowIdx + 1
	for i, nr := range allowNrs {
		idx := dispatch + i
		prog = append(prog, jump(bpfJMP|bpfJEQ|bpfK, nr, uint8(allowIdx-idx-1), 0))
	}
	// sched_getaffinity: the Go runtime queries the calling thread (pid 0).
	// Denying nonzero PIDs also prevents namespace-less workers from using the
	// syscall as a host-process existence oracle.
	a0 := affinityBlock
	a2 := affinityBlock + 2
	prog = append(prog, jump(bpfJMP|bpfJEQ|bpfK, unix.SYS_SCHED_GETAFFINITY,
		0, uint8(tgkillBlock-a0-1)))
	prog = append(prog, stmt(bpfLD|bpfW|bpfABS, offArg0))
	prog = append(prog, jump(bpfJMP|bpfJEQ|bpfK, 0,
		uint8(allowIdx-a2-1), uint8(denyIdx-a2-1)))
	// tgkill: Go's runtime needs to signal arbitrary threads in this process,
	// but never another thread group. pid_t is a 32-bit kernel argument on
	// both supported Linux architectures, so the low word is authoritative.
	t0 := tgkillBlock
	t2 := tgkillBlock + 2
	prog = append(prog, jump(bpfJMP|bpfJEQ|bpfK, unix.SYS_TGKILL, 0, uint8(fcntlBlock-t0-1)))
	prog = append(prog, stmt(bpfLD|bpfW|bpfABS, offArg0))
	prog = append(prog, jump(bpfJMP|bpfJEQ|bpfK, selfTGID,
		uint8(allowIdx-t2-1), uint8(denyIdx-t2-1)))
	// fcntl: allow only descriptor-local commands needed by the worker. Socket
	// signal ownership commands are intentionally excluded.
	f0 := fcntlBlock
	prog = append(prog, jump(bpfJMP|bpfJEQ|bpfK, unix.SYS_FCNTL,
		0, uint8(ioctlBlock-f0-1)))
	prog = append(prog, stmt(bpfLD|bpfW|bpfABS, offArg1))
	for i, cmd := range safeFcntlCommands {
		idx := fcntlBlock + 2 + i
		denyOffset := uint8(0) // a mismatch falls through to the next command
		if i == len(safeFcntlCommands)-1 {
			denyOffset = uint8(denyIdx - idx - 1)
		}
		prog = append(prog, jump(bpfJMP|bpfJEQ|bpfK, cmd,
			uint8(allowIdx-idx-1), denyOffset))
	}
	// ioctl: allowed only when (cmd & 0xFFFF) is in the KVM range.
	// Every jump offset is target-index minus current-index minus one.
	i0 := ioctlBlock
	i3 := ioctlBlock + 3
	i4 := ioctlBlock + 4
	prog = append(prog, jump(bpfJMP|bpfJEQ|bpfK, unix.SYS_IOCTL, 0, uint8(denyIdx-i0-1)))
	// The ioctl REQUEST is the second syscall argument (fd, req, ...):
	// seccomp_data.args[1]. The AL2023 KVM soak caught this reading
	// args[0] (the fd, 12) and denying the whole KVM range.
	prog = append(prog, stmt(bpfLD|bpfW|bpfABS, offArg1)) // i1
	prog = append(prog, stmt(bpfALU|bpfAND|bpfK, 0xFFFF)) // i2
	prog = append(prog, jump(bpfJMP|bpfJGE|bpfK, 0xAE00, 0, uint8(denyIdx-i3-1)))
	prog = append(prog, jump(bpfJMP|bpfJGT|bpfK, 0xAEFF, uint8(denyIdx-i4-1), 0))
	prog = append(prog, stmt(bpfRET|bpfK, retAllow))          // allowIdx
	prog = append(prog, stmt(bpfRET|bpfK, retErrno|sysEPERM)) // denyIdx
	return prog
}

// installSeccomp sets no_new_privs and loads the whitelist filter onto
// every thread (TSYNC). A TSYNC failure leaves threads half-covered, so
// it is reported as a full failure of the tier rather than a partial
// success.
func installSeccomp() error {
	if os.Getenv("WORKERCONF_NOSECCOMP") == "1" {
		// Debug escape hatch (worker postmortem tooling): skip the
		// filter entirely. Never set in production; the report note
		// makes the degradation explicit.
		return errDebugSkipped
	}
	selfTGID := os.Getpid()
	if selfTGID <= 0 {
		return fmt.Errorf("invalid self TGID %d", selfTGID)
	}
	prog := buildFilter(uint32(selfTGID))
	_, _ = fmt.Fprintf(os.Stderr, "workerconf: filter built (%d insns); PR_SET_NO_NEW_PRIVS\n", len(prog))
	if _, _, errno := unix.RawSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return fmt.Errorf("no_new_privs: %w", errno)
	}
	_, _ = fmt.Fprintln(os.Stderr, "workerconf: NNP set; seccomp(SET_MODE_FILTER|TSYNC)")
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	_, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, seccompSetModeFilter, seccompFlagTSYNC,
		uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		return fmt.Errorf("seccomp load (TSYNC): %w", errno)
	}
	_, _ = fmt.Fprintln(os.Stderr, "workerconf: seccomp(2) returned 0")
	return nil
}
