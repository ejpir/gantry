// Copyright 2024 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vhostuser

import (
	"fmt"
	"unsafe"
)

type deviceRegion struct {
	VhostUserMemoryRegion

	Data []byte
}

func (r *deviceRegion) Close() error {
	if r.Data != nil {
		return unmapRegion(r.Data)
	}

	return nil
}

func (r *deviceRegion) configure(fd int, reg *VhostUserMemoryRegion) error {
	if reg.DriverAddr+reg.MemorySize < reg.DriverAddr {
		return fmt.Errorf("overflow 0x%x, sz %x", reg.DriverAddr, reg.MemorySize)
	}

	// MmapOffset is where this region begins inside the shared-memory fd
	// (QEMU packs multiple regions into one fd).  QEMU's libvhost-user maps
	// the fd from offset 0 at size (MemorySize+MmapOffset) and then treats
	// mmap_addr+mmap_offset as the region base -- partly to keep huge-page
	// alignment working.  We reject huge-page fds (see AddMemReg) and
	// instead pass MmapOffset straight to mmap(2), so Data[0] is already
	// the region's first byte and no offset arithmetic is needed later.
	data, err := mapSharedRegion(fd, int64(reg.MmapOffset), int(reg.MemorySize))
	if err != nil {
		return err
	}
	dontDump(data)
	*r = deviceRegion{
		VhostUserMemoryRegion: *reg,
		Data:                  data,
	}
	return nil
}

func (r *deviceRegion) String() string {
	return r.VhostUserMemoryRegion.String()
}

func (r *deviceRegion) containsGuestAddr(guestAddr uint64) bool {
	return guestAddr >= r.GuestPhysAddr && guestAddr-r.GuestPhysAddr < r.MemorySize
}

// FromDriverAddr translates a driver (host-virtual) address to a host
// pointer.  Data starts at the region's first byte (see configure), so we
// do not add MmapOffset here even though QEMU's libvhost-user does.
func (r *deviceRegion) driverRange(driverAddr, size uint64) []byte {
	if driverAddr < r.DriverAddr {
		return nil
	}
	offset := driverAddr - r.DriverAddr
	if offset > uint64(len(r.Data)) || size > uint64(len(r.Data))-offset {
		return nil
	}
	return r.Data[offset : offset+size]
}

func (r *deviceRegion) FromDriverAddr(driverAddr uint64) unsafe.Pointer {
	data := r.driverRange(driverAddr, 1)
	if len(data) == 0 {
		return nil
	}
	return unsafe.Pointer(&data[0])
}
