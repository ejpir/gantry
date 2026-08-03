//go:build windows

// GANTRY PATCH: Windows serves a Linux virtio-fs guest, so use the Linux
// protocol version and output layout.
package fuse

const outputDataSize = 288

const (
	_FUSE_KERNEL_VERSION   = 7
	_MINIMUM_MINOR_VERSION = 12
	_OUR_MINOR_VERSION     = 28
)
