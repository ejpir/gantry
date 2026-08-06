// Copyright 2026 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuse

import "unsafe"

// The server runs on Darwin but speaks the Linux FUSE wire protocol to a
// virtio-fs guest. STATX is therefore a valid guest opcode even though the
// Darwin host has no statx(2) system call.
func doStatx(server *protocolServer, req *request) {
	in := (*StatxIn)(req.inData())
	out := (*StatxOut)(req.outData())
	req.status = server.fileSystem.Statx(req.cancel, in, out)
}

func init() {
	operationHandlers[_OP_STATX] = &operationHandler{
		Name:       "STATX",
		Func:       doStatx,
		InType:     StatxIn{},
		OutType:    StatxOut{},
		InputSize:  unsafe.Sizeof(StatxIn{}),
		OutputSize: unsafe.Sizeof(StatxOut{}),
	}
	checkFixedBufferSize()
}
