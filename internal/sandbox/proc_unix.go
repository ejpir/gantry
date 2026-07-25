//go:build linux || darwin

package sandbox

import (
	"os/exec"
	"syscall"
)

// procAlive reports whether pid exists (kill signal 0).
func procAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
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
