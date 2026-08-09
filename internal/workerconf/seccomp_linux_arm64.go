package workerconf

// auditArch is AUDIT_ARCH_AARCH64: the seccomp_data.arch value this
// build's filter accepts.
const auditArch = 0xC00000B7

// arm64 needs no architecture-only post-confinement syscalls.
func archWhitelist() []uint32 { return nil }
