//go:build windows

package gutil

import (
	"os"

	"golang.org/x/sys/windows"
)

// LockFile takes an exclusive lock on path (creating it), blocking until
// acquired. Closing the returned file releases the lock.
func LockFile(path string) (*os.File, error) {
	return lockFile(path, windows.LOCKFILE_EXCLUSIVE_LOCK)
}

// TryLockFile is LockFile without blocking: it fails immediately when the
// lock is held elsewhere.
func TryLockFile(path string) (*os.File, error) {
	return lockFile(path, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY)
}

// TryLockFD takes an exclusive non-blocking lock on an already-open
// file (the VMM-worker handoff locks the inherited descriptor, not a
// re-opened path).
func TryLockFD(f *os.File) (*os.File, error) {
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol); err != nil {
		return nil, err
	}
	return f, nil
}

func lockFile(path string, flags uint32) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, ol); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
