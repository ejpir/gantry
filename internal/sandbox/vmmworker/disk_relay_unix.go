//go:build linux || darwin

package vmmworker

import (
	"fmt"
	"os"

	"github.com/ejpir/gantry/internal/gutil"
	"golang.org/x/sys/unix"
)

func lockDiskForRelay(source *os.File) (*os.File, error) {
	return gutil.TryLockPrivate(source)
}

func duplicateDiskFile(source *os.File) (*os.File, error) {
	fd, err := unix.FcntlInt(source.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("duplicate writable disk %s: %w", source.Name(), err)
	}
	duplicate := os.NewFile(uintptr(fd), source.Name()+" (broker)")
	if duplicate == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("duplicate writable disk %s: invalid descriptor", source.Name())
	}
	return duplicate, nil
}
