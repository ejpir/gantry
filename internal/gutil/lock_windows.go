//go:build windows

package gutil

import (
	"os"

	"golang.org/x/sys/windows"
)

// LockFile takes an exclusive lock on path (creating it). Closing the
// returned file releases the lock. (Non-blocking attempt: the image
// store reports contention as "another process is building".)
func LockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	ol := new(windows.Overlapped)
	err = windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol)
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
