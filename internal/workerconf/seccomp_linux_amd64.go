package workerconf

import "golang.org/x/sys/unix"

// auditArch is AUDIT_ARCH_X86_64: the seccomp_data.arch value this
// build's filter accepts.
const auditArch = 0xC000003E

// archWhitelist adds the amd64-only TLS setup syscall used by the runtime.
// Path-based newfstatat/faccessat are intentionally excluded.
func archWhitelist() []uint32 {
	return []uint32{
		unix.SYS_ARCH_PRCTL,
	}
}
