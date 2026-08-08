package workerconf

import "golang.org/x/sys/unix"

// auditArch is AUDIT_ARCH_X86_64: the seccomp_data.arch value this
// build's filter accepts.
const auditArch = 0xC000003E

// archWhitelist adds amd64-only syscall numbers: the runtime's TLS
// setup (arch_prctl) and the legacy names Go's syscall wrappers use on
// amd64 (newfstatat, faccessat).
func archWhitelist() []uint32 {
	return []uint32{
		unix.SYS_ARCH_PRCTL,
		unix.SYS_NEWFSTATAT,
		unix.SYS_FACCESSAT,
	}
}
