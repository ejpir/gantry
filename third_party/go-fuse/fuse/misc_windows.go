//go:build windows

// GANTRY PATCH: keep FUSE statuses in the Linux errno namespace used by the
// virtio-fs guest. Windows syscall.Errno values are not wire values.
package fuse

import (
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"
)

func (code Status) String() string {
	if code <= 0 {
		return []string{
			"OK",
			"NOTIFY_POLL",
			"NOTIFY_INVAL_INODE",
			"NOTIFY_INVAL_ENTRY",
			"NOTIFY_STORE_CACHE",
			"NOTIFY_RETRIEVE_CACHE",
			"NOTIFY_DELETE",
			"NOTIFY_RESEND",
			"NOTIFY_INC_EPOCH",
			"NOTIFY_PRUNE",
		}[-code]
	}
	return fmt.Sprintf("%d", int(code))
}

func (code Status) Ok() bool { return code == OK }

func ToStatus(err error) Status {
	if err == nil {
		return OK
	}
	switch err {
	case os.ErrPermission:
		return EPERM
	case os.ErrExist:
		return EEXIST
	case os.ErrNotExist:
		return ENOENT
	case os.ErrInvalid:
		return EINVAL
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return hostErrnoToLinux(errno)
	}
	log.Println("can't convert error type:", err)
	return ENOTSUP
}

func CurrentOwner() *Owner { return &Owner{} }
