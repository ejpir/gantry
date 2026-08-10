package workerconf

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The filter is intentionally assembled without libseccomp: startup is one
// prctl plus one seccomp syscall and the resulting policy is identical on
// every host. Common runtime syscalls are shared; role-specific capabilities
// are explicit below. Path mutation and exec are absent from every profile.
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
	sysENOSYS            = 38
	seccompSetModeFilter = 1
	seccompFlagTSYNC     = 1
	offNr                = 0
	offArch              = 4
	offArg0              = 16
	offArg0Hi            = 20
	offArg1              = 24
	offArg2              = 32
	offArg2Hi            = 36
	socketTypeMask       = 0xf
)

// runtimeWhitelist is the Go runtime, memory, time, signal, descriptor-I/O,
// and netpoll substrate. PID-taking and command-taking calls are handled by
// argument-filtered blocks, never admitted here wholesale.
var runtimeWhitelist = []uint32{
	unix.SYS_READ, unix.SYS_WRITE, unix.SYS_READV, unix.SYS_WRITEV,
	unix.SYS_CLOSE, unix.SYS_DUP, unix.SYS_DUP3,
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
	unix.SYS_FSTAT, unix.SYS_FSTATFS,
	unix.SYS_SHUTDOWN,
	unix.SYS_GETSOCKNAME, unix.SYS_GETPEERNAME,
	unix.SYS_GETSOCKOPT, unix.SYS_SETSOCKOPT,
	unix.SYS_GETUID, unix.SYS_GETEUID, unix.SYS_GETGID, unix.SYS_GETEGID,
}

// whitelist is retained as the VMM profile's unconditionally allowed set.
// Tests inspect it to ensure no path or cross-process authority slips in.
var whitelist = append(append([]uint32{}, runtimeWhitelist...),
	unix.SYS_PREAD64, unix.SYS_PWRITE64, unix.SYS_LSEEK,
	unix.SYS_FSYNC, unix.SYS_FDATASYNC,
	// The VMM receives hot-added descriptors over its dedicated SCM_RIGHTS
	// channel. The network worker has no descriptor-transfer relationship and
	// therefore does not receive these message-oriented capabilities.
	unix.SYS_RECVMSG, unix.SYS_SENDMSG,
)

// networkWhitelist is the host TCP/UDP data plane. socket itself is filtered
// separately to IPv4/IPv6 stream/datagram sockets, excluding AF_PACKET, raw,
// netlink, and new Unix-domain endpoints. Resolver file opens are also
// argument-filtered separately.
var networkWhitelist = []uint32{
	unix.SYS_CONNECT, unix.SYS_BIND, unix.SYS_LISTEN,
	unix.SYS_ACCEPT, unix.SYS_ACCEPT4,
	unix.SYS_SENDTO, unix.SYS_RECVFROM,
	unix.SYS_NEWFSTATAT,
}

// safeFcntlCommands are descriptor-local operations used by the Go runtime
// and net.FileConn. Signal ownership commands are deliberately absent.
var safeFcntlCommands = []uint32{
	unix.F_DUPFD,
	unix.F_GETFD,
	unix.F_SETFD,
	unix.F_GETFL,
	unix.F_SETFL,
	unix.F_DUPFD_CLOEXEC,
}

func stmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k}
}

func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// filterBuilder resolves named forward branches after assembly. Keeping label
// math here avoids security-sensitive hand-maintained offsets whenever a role
// gains one syscall.
type filterBuilder struct {
	program []unix.SockFilter
	labels  map[string]int
	fixups  []filterFixup
}

type filterFixup struct {
	index       int
	true, false string
}

func newFilterBuilder(capacity int) *filterBuilder {
	return &filterBuilder{
		program: make([]unix.SockFilter, 0, capacity),
		labels:  make(map[string]int),
	}
}

func (b *filterBuilder) emit(code uint16, k uint32) {
	b.program = append(b.program, stmt(code, k))
}

func (b *filterBuilder) branch(code uint16, k uint32, onTrue, onFalse string) {
	b.fixups = append(b.fixups, filterFixup{index: len(b.program), true: onTrue, false: onFalse})
	b.program = append(b.program, jump(code, k, 0, 0))
}

func (b *filterBuilder) jumpTo(label string) {
	// Both outcomes target the same label, making this independent of the
	// accumulator's current value without introducing a second assembler path.
	b.branch(bpfJMP|bpfJEQ|bpfK, 0, label, label)
}

func (b *filterBuilder) mark(label string) {
	if _, exists := b.labels[label]; exists {
		panic("workerconf: duplicate seccomp label " + label)
	}
	b.labels[label] = len(b.program)
}

func (b *filterBuilder) resolve() []unix.SockFilter {
	for _, fixup := range b.fixups {
		resolve := func(label string) uint8 {
			if label == "" { // fall through to the next instruction
				return 0
			}
			target, ok := b.labels[label]
			if !ok {
				panic("workerconf: missing seccomp label " + label)
			}
			offset := target - fixup.index - 1
			if offset < 0 || offset > 255 {
				panic(fmt.Sprintf("workerconf: invalid seccomp jump %d -> %s (%d)", fixup.index, label, offset))
			}
			return uint8(offset)
		}
		b.program[fixup.index].Jt = resolve(fixup.true)
		b.program[fixup.index].Jf = resolve(fixup.false)
	}
	return b.program
}

const (
	labelAllow            = "allow"
	labelDeny             = "deny"
	labelKill             = "kill"
	labelENOSYS           = "enosys"
	labelAffinity         = "affinity"
	labelTGKill           = "tgkill"
	labelFcntl            = "fcntl"
	labelClone            = "clone"
	labelCloneFlags       = "clone-flags"
	labelSocket           = "socket"
	labelSocketType       = "socket-type"
	labelSocketProto      = "socket-protocol"
	labelOpen             = "open"
	labelIOCTL            = "ioctl"
	labelPrlimit          = "prlimit"
	labelPrlimitResource  = "prlimit-resource"
	labelPrlimitPointer   = "prlimit-pointer"
	labelPrlimitPointerHi = "prlimit-pointer-hi"
)

// buildFilter preserves the original VMM-filter helper for focused tests.
func buildFilter(selfTGID uint32) []unix.SockFilter {
	return buildFilterFor(DefaultSpec(2, ""), selfTGID)
}

func buildFilterFor(spec Spec, selfTGID uint32) []unix.SockFilter {
	allowNrs := append([]uint32{}, runtimeWhitelist...)
	if spec.Profile == ProfileNetwork {
		allowNrs = append(allowNrs, networkWhitelist...)
	} else {
		allowNrs = append(allowNrs, whitelist[len(runtimeWhitelist):]...)
	}
	allowNrs = append(allowNrs, archWhitelist()...)

	b := newFilterBuilder(len(allowNrs) + 64)
	b.emit(bpfLD|bpfW|bpfABS, offArch)
	b.branch(bpfJMP|bpfJEQ|bpfK, auditArch, "", labelKill)
	b.emit(bpfLD|bpfW|bpfABS, offNr)
	for _, nr := range allowNrs {
		b.branch(bpfJMP|bpfJEQ|bpfK, nr, labelAllow, "")
	}
	b.branch(bpfJMP|bpfJEQ|bpfK, unix.SYS_SCHED_GETAFFINITY, labelAffinity, "")
	b.branch(bpfJMP|bpfJEQ|bpfK, unix.SYS_TGKILL, labelTGKill, "")
	b.branch(bpfJMP|bpfJEQ|bpfK, unix.SYS_FCNTL, labelFcntl, "")
	b.branch(bpfJMP|bpfJEQ|bpfK, unix.SYS_PRLIMIT64, labelPrlimit, "")
	// clone3 stores flags behind a pointer seccomp cannot inspect. ENOSYS is
	// intentional: glibc pthread_create then falls back to clone, whose flags
	// are visible below. EPERM makes glibc fail instead of falling back.
	b.branch(bpfJMP|bpfJEQ|bpfK, unix.SYS_CLONE3, labelENOSYS, "")
	b.branch(bpfJMP|bpfJEQ|bpfK, unix.SYS_CLONE, labelClone, "")
	if spec.Profile == ProfileNetwork {
		b.branch(bpfJMP|bpfJEQ|bpfK, unix.SYS_SOCKET, labelSocket, "")
		b.branch(bpfJMP|bpfJEQ|bpfK, unix.SYS_OPENAT, labelOpen, "")
	} else {
		b.branch(bpfJMP|bpfJEQ|bpfK, unix.SYS_IOCTL, labelIOCTL, "")
	}
	b.jumpTo(labelDeny)

	b.mark(labelAffinity)
	b.emit(bpfLD|bpfW|bpfABS, offArg0)
	b.branch(bpfJMP|bpfJEQ|bpfK, 0, labelAllow, labelDeny)

	b.mark(labelTGKill)
	b.emit(bpfLD|bpfW|bpfABS, offArg0)
	b.branch(bpfJMP|bpfJEQ|bpfK, selfTGID, labelAllow, labelDeny)

	b.mark(labelFcntl)
	b.emit(bpfLD|bpfW|bpfABS, offArg1)
	for _, command := range safeFcntlCommands {
		b.branch(bpfJMP|bpfJEQ|bpfK, command, labelAllow, "")
	}
	b.jumpTo(labelDeny)

	b.mark(labelPrlimit)
	b.emit(bpfLD|bpfW|bpfABS, offArg0)
	b.branch(bpfJMP|bpfJEQ|bpfK, 0, labelPrlimitResource, labelDeny)
	b.mark(labelPrlimitResource)
	b.emit(bpfLD|bpfW|bpfABS, offArg1)
	b.branch(bpfJMP|bpfJEQ|bpfK, unix.RLIMIT_NPROC, labelPrlimitPointer, labelDeny)
	b.mark(labelPrlimitPointer)
	b.emit(bpfLD|bpfW|bpfABS, offArg2)
	b.branch(bpfJMP|bpfJEQ|bpfK, 0, labelPrlimitPointerHi, labelDeny)
	b.mark(labelPrlimitPointerHi)
	b.emit(bpfLD|bpfW|bpfABS, offArg2Hi)
	b.branch(bpfJMP|bpfJEQ|bpfK, 0, labelAllow, labelDeny)

	b.mark(labelClone)
	// A nonzero high word is never a legitimate clone(2) flags value on the
	// supported 64-bit architectures. Then require CLONE_THREAD: the kernel
	// consequently keeps every clone in this TGID and rejects incompatible
	// namespace/exit-signal combinations.
	b.emit(bpfLD|bpfW|bpfABS, offArg0Hi)
	b.branch(bpfJMP|bpfJEQ|bpfK, 0, labelCloneFlags, labelDeny)
	b.mark(labelCloneFlags)
	b.emit(bpfLD|bpfW|bpfABS, offArg0)
	b.emit(bpfALU|bpfAND|bpfK, uint32(unix.CLONE_THREAD))
	b.branch(bpfJMP|bpfJEQ|bpfK, uint32(unix.CLONE_THREAD), labelAllow, labelDeny)

	if spec.Profile == ProfileNetwork {
		b.mark(labelSocket)
		b.emit(bpfLD|bpfW|bpfABS, offArg0)
		b.branch(bpfJMP|bpfJEQ|bpfK, unix.AF_INET, labelSocketType, "")
		b.branch(bpfJMP|bpfJEQ|bpfK, unix.AF_INET6, labelSocketType, labelDeny)

		b.mark(labelSocketType)
		b.emit(bpfLD|bpfW|bpfABS, offArg1)
		b.emit(bpfALU|bpfAND|bpfK, socketTypeMask)
		b.branch(bpfJMP|bpfJEQ|bpfK, unix.SOCK_STREAM, labelSocketProto, "")
		b.branch(bpfJMP|bpfJEQ|bpfK, unix.SOCK_DGRAM, labelSocketProto, labelDeny)

		b.mark(labelSocketProto)
		b.emit(bpfLD|bpfW|bpfABS, offArg2)
		b.branch(bpfJMP|bpfJEQ|bpfK, 0, labelAllow, "")
		b.branch(bpfJMP|bpfJEQ|bpfK, unix.IPPROTO_TCP, labelAllow, "")
		b.branch(bpfJMP|bpfJEQ|bpfK, unix.IPPROTO_UDP, labelAllow, labelDeny)

		b.mark(labelOpen)
		b.emit(bpfLD|bpfW|bpfABS, offArg2)
		const readFlags = unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_LARGEFILE
		b.emit(bpfALU|bpfAND|bpfK, ^uint32(readFlags))
		b.branch(bpfJMP|bpfJEQ|bpfK, 0, labelAllow, labelDeny)
	} else {
		b.mark(labelIOCTL)
		b.emit(bpfLD|bpfW|bpfABS, offArg1)
		b.emit(bpfALU|bpfAND|bpfK, 0xFFFF)
		b.branch(bpfJMP|bpfJGE|bpfK, 0xAE00, "", labelDeny)
		b.branch(bpfJMP|bpfJGT|bpfK, 0xAEFF, labelDeny, labelAllow)
	}

	b.mark(labelDeny)
	b.emit(bpfRET|bpfK, retErrno|sysEPERM)
	b.mark(labelENOSYS)
	b.emit(bpfRET|bpfK, retErrno|sysENOSYS)
	b.mark(labelAllow)
	b.emit(bpfRET|bpfK, retAllow)
	b.mark(labelKill)
	b.emit(bpfRET|bpfK, retKill)
	return b.resolve()
}

// installSeccomp preserves the VMM-profile test helper.
func installSeccomp() error {
	return installSeccompFor(DefaultSpec(2, ""))
}

// installSeccompFor sets no_new_privs and atomically applies the role filter
// to every thread. TSYNC failure is a full tier failure: a partly filtered Go
// process is not a security boundary.
func installSeccompFor(spec Spec) error {
	selfTGID := os.Getpid()
	if selfTGID <= 0 {
		return fmt.Errorf("invalid self TGID %d", selfTGID)
	}
	program := buildFilterFor(spec, uint32(selfTGID))
	_, _ = fmt.Fprintf(os.Stderr, "workerconf: filter built (%d insns); PR_SET_NO_NEW_PRIVS\n", len(program))
	if _, _, errno := unix.RawSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return fmt.Errorf("no_new_privs: %w", errno)
	}
	filter := unix.SockFprog{Len: uint16(len(program)), Filter: &program[0]}
	_, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, seccompSetModeFilter, seccompFlagTSYNC,
		uintptr(unsafe.Pointer(&filter)))
	if errno != 0 {
		return fmt.Errorf("seccomp load (TSYNC): %w", errno)
	}
	return nil
}
