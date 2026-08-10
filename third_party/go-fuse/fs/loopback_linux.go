//go:build linux

// Copyright 2019 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fs

import (
	"context"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

const unix_UTIME_OMIT = unix.UTIME_OMIT

func doCopyFileRange(fdIn int, offIn int64, fdOut int, offOut int64,
	len int, flags int) (uint32, syscall.Errno) {
	count, err := unix.CopyFileRange(fdIn, &offIn, fdOut, &offOut, len, flags)
	return uint32(count), ToErrno(err)
}

func intDev(dev uint32) int {
	return int(dev)
}

var _ = (NodeStatxer)((*LoopbackNode)(nil))

func (n *LoopbackNode) Statx(ctx context.Context, f FileHandle,
	flags uint32, mask uint32,
	out *fuse.StatxOut) syscall.Errno {
	if f != nil {
		if fga, ok := f.(FileStatxer); ok {
			return fga.Statx(ctx, flags, mask, out)
		}
	}

	st := unix.Statx_t{}
	var err error
	if n.pinned() {
		dir, base := relSplitParent(n.relPath())
		dirfd, openErr := openRelDir(n.RootData.RootFD, dir)
		if openErr != nil {
			return ToErrno(openErr)
		}
		defer unix.Close(dirfd)
		if base == "" {
			base = "."
		}
		// A FUSE node represents the directory entry itself. Never let a
		// caller clear AT_SYMLINK_NOFOLLOW and redirect STATX beyond the
		// pinned export through a swapped final symlink.
		err = unix.Statx(dirfd, base, int(flags)|unix.AT_SYMLINK_NOFOLLOW, int(mask), &st)
	} else {
		p := n.path()
		err = unix.Statx(unix.AT_FDCWD, p, int(flags), int(mask), &st)
	}
	if err != nil {
		return ToErrno(err)
	}
	out.FromStatx(&st)
	return OK
}
