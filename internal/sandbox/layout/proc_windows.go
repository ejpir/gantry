//go:build windows

package layout

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// ProcAlive reports whether pid exists and is still running.
func ProcAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259
	return code == stillActive
}

// Terminate asks a daemon to exit: on Windows there is no graceful
// per-process signal; the daemon's own console handlers aside, terminate.
func Terminate(pid int) error {
	return Kill(pid)
}

// Kill force-kills a daemon.
func Kill(pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	return windows.TerminateProcess(h, 1)
}

// DetachDaemon starts the sandbox daemon detached from our console.
func DetachDaemon(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008, // DETACHED_PROCESS
	}
}

// HoldLock takes an exclusive lock on <dir>/vmm.lock; the daemon holds it
// for its whole lifetime so liveness doesn't depend on a bare (recyclable)
// pid.
func HoldLock(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, "vmm.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	ol := new(windows.Overlapped)
	err = windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// LockHeld reports whether some process holds the sandbox lock.
func LockHeld(dir string) bool {
	f, err := os.OpenFile(filepath.Join(dir, "vmm.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	ol := new(windows.Overlapped)
	err = windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol)
	if err != nil {
		return true // held by the daemon
	}
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
	return false
}
