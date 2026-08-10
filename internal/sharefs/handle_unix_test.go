//go:build linux || darwin

package sharefs

import (
	"context"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

type lockProbeFile struct {
	called atomic.Bool
}

func (f *lockProbeFile) Getlk(context.Context, uint64, *fuse.FileLock, uint32, *fuse.FileLock) syscall.Errno {
	f.called.Store(true)
	return 0
}

func (f *lockProbeFile) Setlk(context.Context, uint64, *fuse.FileLock, uint32) syscall.Errno {
	f.called.Store(true)
	return 0
}

func (f *lockProbeFile) Setlkw(context.Context, uint64, *fuse.FileLock, uint32) syscall.Errno {
	f.called.Store(true)
	return 0
}

func TestShareFileDoesNotForwardHostAdvisoryLocks(t *testing.T) {
	probe := new(lockProbeFile)
	file := &shareFile{FileHandle: probe, export: &Export{}}
	lock := new(fuse.FileLock)

	if errno := file.Getlk(context.Background(), 1, lock, 0, new(fuse.FileLock)); errno != syscall.ENOTSUP {
		t.Fatalf("Getlk errno = %v, want ENOTSUP", errno)
	}
	if errno := file.Setlk(context.Background(), 1, lock, 0); errno != syscall.ENOTSUP {
		t.Fatalf("Setlk errno = %v, want ENOTSUP", errno)
	}
	if errno := file.Setlkw(context.Background(), 1, lock, 0); errno != syscall.ENOTSUP {
		t.Fatalf("Setlkw errno = %v, want ENOTSUP", errno)
	}
	if probe.called.Load() {
		t.Fatal("share wrapper forwarded a host advisory-lock operation")
	}
}
