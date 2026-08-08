package workerconf

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Hand-rolled seccomp-bpf whitelist (no libseccomp cgo dependency — the
// list is small and static). Design notes:
//
//   - open/openat2 ARE allowed: the share hub serves via dirfd-relative
//     opens against FD-pinned roots. Absolute paths are neutered by the
//     private tmpfs root (mount tier), and cwd is "/". If the mount
//     tier was unavailable the fs probes report unenforced honestly.
//   - socket/connect/bind/listen/accept are absent: the worker's data
//     plane is inherited descriptors only (net-dial probe gets EPERM).
//   - execve/execveat are absent: fork-only children inherit the same
//     namespaces and filter and cannot escape or do useful work.
//   - clone/clone3 are allowed UNMASKED: the Go runtime spawns threads
//     lazily after Apply, and clone3's flags live behind a pointer that
//     seccomp cannot dereference. execve is the real boundary.
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
	offArch              = 4 // seccomp_data.arch
	offNr                = 0 // seccomp_data.nr
	offArg0              = 16
)

// whitelist is the syscall set a VMM worker needs post-Apply: the Go
// runtime (threads, GC, netpoll, timers), descriptor I/O on inherited
// fds, the share hub's dirfd-relative serving ops, and the KVM ioctl
// range (filtered separately). Names resolve per-arch via x/sys; the
// arch files add their arch-only entries (fstatat variants, arch_prctl).
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
	unix.SYS_SIGALTSTACK, unix.SYS_TGKILL,
	unix.SYS_EPOLL_CREATE1, unix.SYS_EPOLL_CTL, unix.SYS_EPOLL_PWAIT,
	unix.SYS_PPOLL, unix.SYS_PSELECT6, unix.SYS_EVENTFD2,
	unix.SYS_GETRANDOM, unix.SYS_RSEQ, unix.SYS_MEMBARRIER,
	unix.SYS_SET_ROBUST_LIST, unix.SYS_SET_TID_ADDRESS,
	unix.SYS_SCHED_GETAFFINITY,
	unix.SYS_EXIT, unix.SYS_EXIT_GROUP,
	unix.SYS_CLONE, unix.SYS_CLONE3,
	unix.SYS_OPENAT, unix.SYS_OPENAT2,
	unix.SYS_FSTAT, unix.SYS_STATX, unix.SYS_FSTATFS, unix.SYS_GETDENTS64,
	unix.SYS_READLINKAT, unix.SYS_FACCESSAT2, unix.SYS_GETCWD,
	unix.SYS_FCHMOD, unix.SYS_FCHMODAT, unix.SYS_FCHOWN, unix.SYS_FCHOWNAT,
	unix.SYS_UTIMENSAT, unix.SYS_FALLOCATE,
	unix.SYS_FSYNC, unix.SYS_FDATASYNC, unix.SYS_FLOCK, unix.SYS_FCNTL,
	unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2, unix.SYS_LINKAT,
	unix.SYS_SYMLINKAT, unix.SYS_UNLINKAT, unix.SYS_MKDIRAT, unix.SYS_MKNODAT,
	unix.SYS_FTRUNCATE, unix.SYS_COPY_FILE_RANGE,
	unix.SYS_FGETXATTR, unix.SYS_FSETXATTR, unix.SYS_FLISTXATTR,
	unix.SYS_FREMOVEXATTR,
	unix.SYS_RECVMSG, unix.SYS_SENDMSG, unix.SYS_SHUTDOWN,
	unix.SYS_GETSOCKNAME, unix.SYS_GETPEERNAME,
	unix.SYS_GETUID, unix.SYS_GETEUID, unix.SYS_GETGID, unix.SYS_GETEGID,
}

func stmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: 0, Jf: 0, K: k}
}

func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// buildFilter assembles the BPF program. Jump targets are computed from
// final label positions so the jeq chain length is free to grow.
func buildFilter() []unix.SockFilter {
	allowNrs := append(append([]uint32{}, whitelist...), archWhitelist()...)
	prog := make([]unix.SockFilter, 0, len(allowNrs)+12)
	// 0: arch check — a foreign-arch process image gets killed outright.
	prog = append(prog, stmt(bpfLD|bpfW|bpfABS, offArch))
	prog = append(prog, jump(bpfJMP|bpfJEQ|bpfK, auditArch, 1, 0))
	prog = append(prog, stmt(bpfRET|bpfK, retKill))
	// 3: nr dispatch.
	prog = append(prog, stmt(bpfLD|bpfW|bpfABS, offNr))
	dispatch := len(prog)
	// Reserve the jeq chain; jump offsets need ALLOW's final index.
	ioctlBlock := dispatch + len(allowNrs)
	allowIdx := ioctlBlock + 5 // LD,AND,JGE,JGT + JEQ head = 5 instrs
	denyIdx := allowIdx + 1
	for i, nr := range allowNrs {
		idx := dispatch + i
		prog = append(prog, jump(bpfJMP|bpfJEQ|bpfK, nr, uint8(allowIdx-idx-1), 0))
	}
	// ioctl: allowed only when (cmd & 0xFFFF) is in the KVM range.
	// Every jump offset is target-index minus current-index minus one.
	i0 := ioctlBlock
	i3 := ioctlBlock + 3
	i4 := ioctlBlock + 4
	prog = append(prog, jump(bpfJMP|bpfJEQ|bpfK, unix.SYS_IOCTL, 0, uint8(denyIdx-i0-1)))
	prog = append(prog, stmt(bpfLD|bpfW|bpfABS, offArg0)) // i1
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
	prog := buildFilter()
	if _, _, errno := unix.RawSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return fmt.Errorf("no_new_privs: %w", errno)
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	_, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, seccompSetModeFilter, seccompFlagTSYNC,
		uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		return fmt.Errorf("seccomp load (TSYNC): %w", errno)
	}
	return nil
}
