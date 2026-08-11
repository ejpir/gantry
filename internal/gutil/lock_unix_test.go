//go:build linux || darwin

package gutil

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func writableImage(t *testing.T) (string, *os.File) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rwlayer.ext4")
	if err := os.WriteFile(path, make([]byte, 1<<16), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return path, f
}

// A writable disk that nobody else holds must lock on the first attempt.
// Stacking a POSIX record lock on top of the flock used to fail here on
// darwin, where both lock forms share one advisory list per vnode: the
// process conflicted with its own flock and every rwlayer boot died with
// EAGAIN ("resource temporarily unavailable").
func TestTryLockFDLocksUncontendedFile(t *testing.T) {
	_, f := writableImage(t)
	if _, err := TryLockFD(f); err != nil {
		t.Fatalf("TryLockFD on an uncontended file: %v", err)
	}
}

func TestTryLockFDRejectsSecondDescription(t *testing.T) {
	path, f := writableImage(t)
	if _, err := TryLockFD(f); err != nil {
		t.Fatal(err)
	}
	other, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	if _, err := TryLockFD(other); err == nil {
		t.Fatal("a second open description acquired the exclusive lock")
	}
}

// The supervisor's lock must outlive anything the worker can do with the
// descriptor it inherits: the child shares that open file description, so a
// lock taken on it would be the child's to release.
func TestTryLockPrivateSurvivesInheritedDescription(t *testing.T) {
	path, f := writableImage(t)
	lock, err := TryLockPrivate(f)
	if err != nil {
		t.Fatalf("TryLockPrivate: %v", err)
	}
	defer func() { _ = lock.Close() }()
	if lock == f {
		t.Fatal("TryLockPrivate returned the caller's description")
	}

	// Everything the worker could reach through its inherited descriptor.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	other, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	if _, err := TryLockFD(other); err == nil {
		t.Fatal("supervisor lock was released by the inherited description")
	}

	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := TryLockFD(other); err != nil {
		t.Fatalf("lock outlived the supervisor's descriptor: %v", err)
	}
}

func TestTryLockPrivateRejectsSwappedPath(t *testing.T) {
	path, f := writableImage(t)
	replacement := filepath.Join(filepath.Dir(path), "other.ext4")
	if err := os.WriteFile(replacement, make([]byte, 1<<16), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	lock, err := TryLockPrivate(f)
	if err == nil {
		_ = lock.Close()
		t.Fatal("TryLockPrivate locked a file swapped in behind the descriptor")
	}
}
