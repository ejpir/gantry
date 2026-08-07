//go:build (linux && arm64) || darwin

package vmm

// PSTATE at boot: EL1h (0b0101), all exceptions masked (D A I F = 0x3c0).
// Shared by the two arm64 backends (KVM on Linux, Hypervisor.framework on
// macOS); the x86 paths have no PSTATE.
const pstateEL1hMask = 0x3c5
