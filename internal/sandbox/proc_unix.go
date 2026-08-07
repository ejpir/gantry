//go:build linux || darwin

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// procAlive reports whether pid exists (kill signal 0).
func procAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	// EPERM still means the process exists; this is common for PID 1 in
	// hosted/containerized CI environments where signaling it is forbidden.
	return err == nil || err == syscall.EPERM
}

// procTerminate asks a daemon to exit gracefully.
func procTerminate(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}

// procKill force-kills a daemon.
func procKill(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}

// detachDaemon starts the sandbox daemon detached from our session.
func detachDaemon(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// holdSandboxLock takes an exclusive flock on <dir>/vmm.lock; the daemon
// holds it for its whole lifetime so liveness doesn't depend on a bare
// (recyclable) pid.
func holdSandboxLock(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, "vmm.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// sandboxLockHeld reports whether some process holds the sandbox lock.
func sandboxLockHeld(dir string) bool {
	f, err := os.OpenFile(filepath.Join(dir, "vmm.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true // held by the daemon
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false
}
