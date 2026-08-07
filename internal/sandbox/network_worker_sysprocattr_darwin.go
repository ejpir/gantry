package sandbox

import "syscall"

// workerSysProcAttr: macOS has no PR_SET_PDEATHSIG; the worker relies on
// control/data channel EOF plus the daemon's reaping on teardown.
func workerSysProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{} }
