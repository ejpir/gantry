//go:build linux || darwin

package gutil

import (
	"fmt"
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

// TryLockFD takes an exclusive non-blocking flock on an already-open
// file. The lock rides the open file description, so it survives fd
// inheritance across fork/exec and is released when the last duplicate
// closes.
//
// flock is deliberately the only form used here. A POSIX record lock
// (fcntl F_SETLK) is owned by the process rather than by the description,
// which reads like the better fit for "a split VMM child must not be able
// to release its supervisor's lock" — but the two forms cannot be stacked
// on one file: on darwin (and the BSDs) flock and fcntl locks share a
// single advisory-lock list per vnode with different owner identities (the
// open file for flock, the process for fcntl), so a process that has
// flock'd a file conflicts with ITSELF when it then requests the record
// lock and F_SETLK fails with EAGAIN. Linux keeps the two lock spaces
// independent, which is why stacking them looked correct there. Record
// locks are also released by closing ANY descriptor for the file in the
// process, so an unrelated re-open+close silently drops them.
//
// Supervisor ownership is structural instead: TryLockPrivate holds the
// lock on a description the untrusted worker never inherits.
func TryLockFD(f *os.File) (*os.File, error) {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, err
	}
	return f, nil
}

// TryLockPrivate locks the file behind f on a SEPARATE open file
// description and returns that description; the caller closes it to
// release. Because flock ownership follows the description, a process that
// inherits (or dups) f cannot unlock what the returned description holds —
// the trusted supervisor stays the lock owner even when it hands the disk
// descriptor to an untrusted VMM worker.
//
// The re-open goes through the path, so it is checked against f's identity:
// a swapped path yields a different file and is refused rather than locked.
func TryLockPrivate(f *os.File) (*os.File, error) {
	want, err := f.Stat()
	if err != nil {
		return nil, err
	}
	private, err := os.OpenFile(f.Name(), os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	got, err := private.Stat()
	if err != nil {
		_ = private.Close()
		return nil, err
	}
	if !os.SameFile(want, got) {
		_ = private.Close()
		return nil, fmt.Errorf("%s changed identity between open and lock", f.Name())
	}
	if err := syscall.Flock(int(private.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = private.Close()
		return nil, err
	}
	return private, nil
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
