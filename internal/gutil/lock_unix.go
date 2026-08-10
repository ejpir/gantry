//go:build linux || darwin

package gutil

import (
	"io"
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

// TryLockFD takes both exclusive non-blocking lock forms. flock catches a
// second open description in this process; the POSIX record lock is owned by
// the process, so a split VMM child cannot release the trusted supervisor's
// lock even though it inherits a descriptor for the same file.
func TryLockFD(f *os.File) (*os.File, error) {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, err
	}
	lock := syscall.Flock_t{
		Type:   syscall.F_WRLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    0,
	}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lock); err != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return nil, err
	}
	return f, nil
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
