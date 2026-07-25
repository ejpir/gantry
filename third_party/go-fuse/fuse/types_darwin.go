// Copyright 2016 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuse

// This vendored build runs on a Darwin host but serves a Linux virtio-fs
// guest. The structs and capability bits in this file therefore deliberately
// use the Linux FUSE wire ABI; only conversion from Darwin host statfs data is
// host-specific.

import "syscall"

const (
	// Linux guest errno values, not Darwin's ENOATTR/ENODATA values.
	ENODATA   = Status(61)
	ENOATTR   = Status(61)
	EREMOTEIO = Status(121)
)

type Attr struct {
	Ino    uint64
	Size   uint64
	Blocks uint64
	Atime  uint64
	Mtime  uint64
	Ctime  uint64

	Atimensec uint32
	Mtimensec uint32
	Ctimensec uint32
	Mode      uint32
	Nlink     uint32
	Owner
	Rdev    uint32
	Blksize uint32
	Padding uint32
}

type SetAttrIn struct {
	SetAttrInCommon
}

type SetXAttrIn struct {
	InHeader
	Size  uint32
	Flags uint32
}

type GetXAttrIn struct {
	InHeader
	Size    uint32
	Padding uint32
}

// Linux FUSE_INIT capability bits.
const (
	CAP_NO_OPENDIR_SUPPORT  = (1 << 24)
	CAP_EXPLICIT_INVAL_DATA = (1 << 25)
	CAP_MAP_ALIGNMENT       = (1 << 26)
	CAP_SUBMOUNTS           = (1 << 27)
	CAP_HANDLE_KILLPRIV_V2  = (1 << 28)
	CAP_SETXATTR_EXT        = (1 << 29)
	CAP_INIT_EXT            = (1 << 30)
	CAP_INIT_RESERVED       = (1 << 31)

	// macFUSE-only feature; never negotiated with the Linux guest.
	CAP_RENAME_SWAP = 0
)

// Kept for opcode_darwin.go's host-only MONITOR entry; a Linux guest never
// emits this operation.
type MonitorIn struct {
	InHeader
	Flags   uint32
	Padding uint32
}

func (s *StatfsOut) FromStatfsT(statfs *syscall.Statfs_t) {
	s.Blocks = statfs.Blocks
	s.Bfree = statfs.Bfree
	s.Bavail = statfs.Bavail
	s.Files = statfs.Files
	s.Ffree = statfs.Ffree
	s.Bsize = uint32(statfs.Iosize)
	s.Frsize = uint32(statfs.Bsize)
	s.NameLen = 255
}

func (o *InitOut) setFlags(flags uint64) {
	o.Flags = uint32(flags) | CAP_INIT_EXT
	o.Flags2 = uint32(flags >> 32)
}
