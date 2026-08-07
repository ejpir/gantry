package sandbox

import "syscall"

// workerSysProcAttr installs parent-death semantics: a supervisor crash
// can never leave a network worker running (control/data EOF is the
// portable belt; PR_SET_PDEATHSIG is the Linux suspenders).
func workerSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
