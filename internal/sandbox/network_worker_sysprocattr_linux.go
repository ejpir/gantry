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

// workerConfineProcAttr extends the worker's process attributes with a
// user+mount namespace for self-confinement (docs/worker-confinement.md):
// uid/gid 0 inside map to the real user outside, so /dev/kvm group
// permissions and same-user signaling keep working, and the namespace
// hands the worker CAP_SYS_ADMIN over its private mount table for the
// tmpfs pivot_root. Ubuntu 24.04+ AppArmor may deny this — the spawn
// path retries without namespaces in auto mode and the worker reports
// the degraded tier honestly.
func workerConfineProcAttr(attr *syscall.SysProcAttr) {
	attr.Cloneflags |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS
	attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
	attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
}
