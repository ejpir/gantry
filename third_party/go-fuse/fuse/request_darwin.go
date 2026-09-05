// Copyright 2016 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuse

// GANTRY PATCH: Darwin serves a Linux virtio-fs guest. Linux STATX is the
// largest fixed reply currently registered and does not fit the macFUSE-sized
// inline buffer.
const outputDataSize = 288

const (
	_FUSE_KERNEL_VERSION   = 7
	_MINIMUM_MINOR_VERSION = 12
	// This Darwin process serves a Linux virtio-fs guest, not macFUSE. Keep
	// the negotiated minor aligned with the Linux server implementation so
	// INIT replies include flags2 and the rest of the extended Linux ABI.
	_OUR_MINOR_VERSION = 28
)
