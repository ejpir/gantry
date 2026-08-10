//go:build !freebsd && !windows

// Copyright 2024 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package fs

import (
	"context"
	"syscall"

	"golang.org/x/sys/unix"
)

var _ = (NodeListxattrer)((*LoopbackNode)(nil))

func (n *LoopbackNode) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	if n.pinned() {
		var size int
		errno := n.withPinnedXattr(func(fd int) error {
			var err error
			size, err = unix.Flistxattr(fd, dest)
			return err
		})
		if errno != 0 {
			return 0, errno
		}
		return uint32(size), 0
	}
	sz, err := unix.Llistxattr(n.path(), dest)
	if err != nil {
		return 0, ToErrno(err)
	}
	return uint32(sz), 0
}
