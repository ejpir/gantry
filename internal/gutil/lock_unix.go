//go:build linux || darwin

package gutil

import (
	"os"
	"syscall"
)

// LockFile takes an exclusive flock on path (creating it), blocking until
// acquired. Closing the returned file releases the lock.
func LockFile(path string) (*os.File, error) {
	return flock(path, syscall.LOCK_EX)
}

// TryLockFile is LockFile without blocking: it fails immediately when the
// lock is held elsewhere.
func TryLockFile(path string) (*os.File, error) {
	return flock(path, syscall.LOCK_EX|syscall.LOCK_NB)
}

func flock(path string, how int) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
