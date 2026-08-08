package workerconf

import "golang.org/x/sys/unix"

// auditArch is AUDIT_ARCH_AARCH64: the seccomp_data.arch value this
// build's filter accepts.
const auditArch = 0xC00000B7

// archWhitelist adds the arm64 fstatat number (x/sys exposes it as
// SYS_NEWFSTATAT on both architectures, but the arm64 generic ABI has
// no faccessat/futimens, so those stay amd64-only).
func archWhitelist() []uint32 {
	return []uint32{
		unix.SYS_NEWFSTATAT,
	}
}
