// Copyright 2019 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fs

import (
	"errors"
	"os"
	"syscall"

	"github.com/hanwen/go-fuse/v2/internal/xattr"
)

// OK is the Errno return value to indicate absense of errors.
var OK = syscall.Errno(0)

// ToErrno extracts an errno in the HOST namespace. The raw bridge translates
// it exactly once to the Linux guest namespace before putting it on the wire.
func ToErrno(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}
	switch err {
	case os.ErrPermission:
		return syscall.EPERM
	case os.ErrExist:
		return syscall.EEXIST
	case os.ErrNotExist:
		return syscall.ENOENT
	case os.ErrInvalid:
		return syscall.EINVAL
	default:
		return syscall.ENOTSUP
	}
}

// RENAME_EXCHANGE is a flag argument for renameat2()
const RENAME_EXCHANGE = 0x2

// seek to the next data
const _SEEK_DATA = 3

// seek to the next hole
const _SEEK_HOLE = 4

// ENOATTR indicates that an extended attribute was not present.
const ENOATTR = xattr.ENOATTR
