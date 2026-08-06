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
	_OUR_MINOR_VERSION     = 19
)
