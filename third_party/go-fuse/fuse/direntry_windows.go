//go:build windows

// GANTRY PATCH: directory entries on the virtio-fs wire use the Linux
// getdents64 layout even when the host is Windows.
package fuse

import "unsafe"

type dirent struct {
	Ino    uint64
	Off    int64
	Reclen uint16
	Type   uint8
	Name   [1]uint8
}

func (de *dirent) nameLength() int {
	return int(de.Reclen) - int(unsafe.Offsetof(dirent{}.Name))
}
