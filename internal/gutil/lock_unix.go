//go:build linux || darwin

package gutil

import (
	"os"
	"syscall"
)

// LockFile takes an exclusive flock on path (creating it), blocking until
// acquired. Closing the returned file releases the lock.
func LockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
