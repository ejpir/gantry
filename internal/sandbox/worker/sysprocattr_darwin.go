package worker

import "syscall"

// SysProcAttr: macOS has no PR_SET_PDEATHSIG; the worker relies on
// control/data channel EOF plus the daemon's reaping on teardown.
func SysProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{} }

// ConfineProcAttr is a no-op on darwin: macOS confinement is
// self-applied by the worker via Seatbelt (M2), not by spawn-time
// attributes.
func ConfineProcAttr(*syscall.SysProcAttr) {}
