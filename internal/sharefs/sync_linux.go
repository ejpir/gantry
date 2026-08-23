//go:build linux

package sharefs

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

func syncExport(export *Export) syscall.Errno {
	if export == nil || !export.usable() || export.watchRootFD < 0 {
		return syscall.ESTALE
	}
	if err := unix.Syncfs(export.watchRootFD); err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			return errno
		}
		return syscall.EIO
	}
	return 0
}
