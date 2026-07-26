//go:build windows

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// procAlive reports whether pid exists and is still running.
func procAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259
	return code == stillActive
}

// procTerminate asks a daemon to exit: on Windows there is no graceful
// per-process signal; the daemon's own console handlers aside, terminate.
func procTerminate(pid int) error {
	return procKill(pid)
}

// procKill force-kills a daemon.
func procKill(pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}

// detachDaemon starts the sandbox daemon detached from our console.
func detachDaemon(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008, // DETACHED_PROCESS
	}
}

// holdSandboxLock takes an exclusive lock on <dir>/vmm.lock; the daemon
// holds it for its whole lifetime so liveness doesn't depend on a bare
// (recyclable) pid.
func holdSandboxLock(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, "vmm.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	ol := new(windows.Overlapped)
	err = windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol)
	if err != nil {
		f.Close()
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
	defer f.Close()
	ol := new(windows.Overlapped)
	err = windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol)
	if err != nil {
		return true // held by the daemon
	}
	windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
	return false
}
