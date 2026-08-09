package sandbox

import (
	"os"
	"syscall"
)

// workerSysProcAttr installs parent-death semantics: a supervisor crash
// can never leave a network worker running (control/data EOF is the
// portable belt; PR_SET_PDEATHSIG is the Linux suspenders).
func workerSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

// workerConfineProcAttr extends the worker's process attributes with user,
// mount, and PID namespaces for self-confinement
// (docs/worker-confinement.md):
// uid/gid 0 inside map to the real user outside, preserving ownership checks
// on inherited resources, and the namespace hands the worker CAP_SYS_ADMIN
// over its private mount table for the tmpfs pivot_root. The PID namespace
// prevents tgkill and other PID-taking interfaces from addressing processes
// outside the worker; the worker is PID 1 and Go-created threads remain in
// that namespace. Ubuntu 24.04+ AppArmor may deny this — the spawn path
// retries without namespaces in auto mode and the worker reports the degraded
// tier honestly.
func workerConfineProcAttr(attr *syscall.SysProcAttr) {
	attr.Cloneflags |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID
	attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
	attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
}
