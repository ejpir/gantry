// Copyright 2024 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vhostuser

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

type deviceRegions struct {
	mu sync.Mutex
	// sorted by GuestPhysAddr; updated atomically so readers need no lock.
	regions atomic.Pointer[[]deviceRegion]
}

func (d *deviceRegions) load() []deviceRegion {
	if p := d.regions.Load(); p != nil {
		return *p
	}
	return nil
}

func (d *deviceRegions) dumpRegions() {
	regs := d.load()
	for i := range regs {
		log.Printf("region %d: %v", i, &regs[i])
	}
}

func (d *deviceRegions) Close() error {
	var retErr error
	for _, r := range d.load() {
		if err := r.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}
	return retErr
}

func (d *deviceRegions) FromDriverAddr(driverAddr uint64) unsafe.Pointer {
	for _, r := range d.load() {
		p := r.FromDriverAddr(driverAddr)
		if p != nil {
			return p
		}
	}
	return nil
}

func (d *deviceRegions) FromDriverRange(driverAddr, size uint64) []byte {
	for _, r := range d.load() {
		if data := r.driverRange(driverAddr, size); data != nil {
			return data
		}
	}
	return nil
}

func (d *deviceRegions) FromGuestAddr(guestAddr uint64, sz uint64) []byte {
	regs := d.load()
	idx := findRegionByGuestAddr(regs, guestAddr)
	if idx >= len(regs) {
		return nil
	}
	r := regs[idx]
	if !r.containsGuestAddr(guestAddr) {
		return nil
	}

	offset := guestAddr - r.GuestPhysAddr
	available := uint64(len(r.Data)) - offset
	if sz > available {
		sz = available
	}
	return r.Data[offset : offset+sz]
}

// findRegionByGuestAddr returns the index of the region that may contain
// guestAddr.  The caller must check containsGuestAddr on the result.
func findRegionByGuestAddr(regs []deviceRegion, guestAddr uint64) int {
	return sort.Search(len(regs),
		func(i int) bool {
			return guestAddr < regs[i].GuestPhysAddr+regs[i].MemorySize
		})
}

func (d *deviceRegions) AddMemReg(fd int, reg *VhostUserMemoryRegion) error {
	defer syscall.Close(fd)
	if reg == nil || reg.MemorySize == 0 || reg.GuestPhysAddr+reg.MemorySize < reg.GuestPhysAddr ||
		reg.DriverAddr+reg.MemorySize < reg.DriverAddr {
		return fmt.Errorf("invalid memory region")
	}
	if hps := getFDHugepagesize(fd); hps != 0 {
		return fmt.Errorf("huge pages")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	old := d.load()
	if len(old) == int(d.GetMaxMemslots()) {
		return fmt.Errorf("out of memory slots")
	}
	newEnd := reg.GuestPhysAddr + reg.MemorySize
	newDriverEnd := reg.DriverAddr + reg.MemorySize
	total := reg.MemorySize
	if total > maxMappedMemoryBytes {
		return fmt.Errorf("mapped memory exceeds %d bytes", maxMappedMemoryBytes)
	}
	for index := range old {
		oldEnd := old[index].GuestPhysAddr + old[index].MemorySize
		if reg.GuestPhysAddr < oldEnd && old[index].GuestPhysAddr < newEnd {
			return fmt.Errorf("overlapping guest memory region")
		}
		oldDriverEnd := old[index].DriverAddr + old[index].MemorySize
		if reg.DriverAddr < oldDriverEnd && old[index].DriverAddr < newDriverEnd {
			return fmt.Errorf("overlapping driver memory region")
		}
		if old[index].MemorySize > maxMappedMemoryBytes-total {
			return fmt.Errorf("mapped memory exceeds %d bytes", maxMappedMemoryBytes)
		}
		total += old[index].MemorySize
	}
	// Validate policy and ranges before mmap so rejected registrations cannot
	// consume address space or leave a latent SIGBUS beyond the fd extent.
	var dr deviceRegion
	if err := dr.configure(fd, reg); err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = dr.Close()
		}
	}()

	idx := findRegionByGuestAddr(old, reg.GuestPhysAddr)
	newRegs := make([]deviceRegion, len(old)+1)
	copy(newRegs, old[:idx])
	newRegs[idx] = dr
	copy(newRegs[idx+1:], old[idx:])
	d.regions.Store(&newRegs)
	keep = true
	return nil
}

// Gantry creates one supervisor-owned shared-RAM object and its in-tree vhost
// frontend registers that object as a single region. Advertising additional
// slots would only give a compromised VMM worker more mapping authority.
const (
	MAX_MEM_SLOTS        = 1
	maxMappedMemoryBytes = uint64(1 << 40) // Gantry's VM-wide 1 TiB ceiling.
)

func (d *deviceRegions) GetMaxMemslots() uint64 {
	return MAX_MEM_SLOTS
}
