package sandbox

import "syscall"

// workerSysProcAttr: macOS has no PR_SET_PDEATHSIG; the worker relies on
// control/data channel EOF plus the daemon's reaping on teardown.
func workerSysProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{} }

// workerConfineProcAttr is a no-op on darwin: macOS confinement is
// self-applied by the worker via Seatbelt (M2), not by spawn-time
// attributes.
func workerConfineProcAttr(*syscall.SysProcAttr) {}
