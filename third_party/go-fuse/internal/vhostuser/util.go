// Copyright 2024 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vhostuser

import (
	"fmt"
	"log"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const _HUGETLBFS_MAGIC = 0x958458f6

func getFDHugepagesize(fd int) int {
	var fs syscall.Statfs_t
	var err error
	for {
		err = syscall.Fstatfs(fd, &fs)
		if err != syscall.EINTR {
			break
		}
	}

	if err == nil && fs.Type == _HUGETLBFS_MAGIC {
		return int(fs.Bsize)
	}
	return 0
}

type inputSnapshot struct {
	storage []byte
	iov     [maxVhostChainDescriptors][]byte
}

var inputSnapshotPool = sync.Pool{New: func() any { return new(inputSnapshot) }}

func snapshotInputs(parts [][]byte) (*inputSnapshot, error) {
	if len(parts) > maxVhostChainDescriptors {
		return nil, fmt.Errorf("%d input vectors exceed cap", len(parts))
	}
	total := 0
	for _, part := range parts {
		if len(part) > maxVhostChainBytes-total {
			return nil, fmt.Errorf("input exceeds %d bytes", maxVhostChainBytes)
		}
		total += len(part)
	}
	snapshot := inputSnapshotPool.Get().(*inputSnapshot)
	if cap(snapshot.storage) < total {
		snapshot.storage = make([]byte, total)
	} else {
		snapshot.storage = snapshot.storage[:total]
	}
	clear(snapshot.iov[:])
	offset := 0
	for index, part := range parts {
		next := offset + len(part)
		snapshot.iov[index] = snapshot.storage[offset:next]
		copy(snapshot.iov[index], part)
		offset = next
	}
	return snapshot, nil
}

func releaseInputSnapshot(snapshot *inputSnapshot) {
	if snapshot == nil {
		return
	}
	clear(snapshot.iov[:])
	inputSnapshotPool.Put(snapshot)
}

func composeMask(fs []int) uint64 {
	var mask uint64
	for _, f := range fs {
		mask |= (uint64(0x1) << f)
	}
	return mask
}

// readLoop reads kick eventfd notifications and processes virtqueue elements.
//
// Locking follows the virtiofsd model (fuse_virtio.c):
//   - dispatchMu read lock is held only while draining the avail ring
//     (popQueue calls).  This blocks concurrent control-plane messages
//     (ADD_MEM_REG, SET_VRING_*, etc.) which take the write lock.
//   - The lock is released before spawning request goroutines, so
//     control-plane messages can be processed concurrently with in-flight
//     FUSE requests.  That is safe because ADD_MEM_REG only adds regions
//     and never invalidates pointers already held by a request.
func (vq *Virtq) readLoop(handle func(data *VirtqElem) int) {
	defer close(vq.control.done)
	pollFDs := []unix.PollFd{{Fd: int32(vq.KickFD), Events: unix.POLLIN}}
	for {
		select {
		case <-vq.control.cancel:
			return
		default:
		}
		nReady, err := unix.Poll(pollFDs, 100)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			log.Printf("poll kick fd: %v", err)
			return
		}
		if nReady == 0 {
			continue
		}
		if pollFDs[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return
		}
		if pollFDs[0].Revents&unix.POLLIN == 0 {
			continue
		}

		var id [8]byte
		n, err := syscall.Read(vq.KickFD, id[:])
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			continue
		}
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			log.Printf("read kick fd: %v", err)
			return
		}
		if n == 0 {
			return
		}

		// Process the batch without holding any lock. Notification buffers are
		// intentionally parked until the filesystem emits a reverse
		// invalidation; ordinary request elements retain concurrent dispatch.
		for _, data := range vq.popBatch() {
			if vq.notifications != nil {
				vq.notifications.add(data)
				continue
			}
			vq.requests.Add(1)
			go func(data *VirtqElem) {
				defer vq.requests.Done()
				vq.processElements(data, handle)
			}(data)
		}
	}
}

func (vq *Virtq) processElements(data *VirtqElem, handle func(data *VirtqElem) int) {
	vq.completionMu.RLock()
	defer vq.completionMu.RUnlock()
	snapshot, err := snapshotInputs(data.Read)
	if err != nil {
		log.Printf("snapshot FUSE input: %v", err)
		vq.pushQueue(data, 0)
		vq.queueNotify()
		return
	}
	data.Read = snapshot.iov[:len(data.Read)]
	defer releaseInputSnapshot(snapshot)
	for _, e := range data.Write {
		clear(e)
	}

	if *vq.Debug {
		for i, e := range data.Read {
			log.Printf("read %d: %q (%d)", i, e, len(e))
		}
		outlens := []int{}
		for _, e := range data.Write {
			outlens = append(outlens, len(e))
		}
		log.Printf("id %d: write space: %v", data.index, outlens)
	}
	n := 0
	if handle != nil {
		n = handle(data)
	}
	if *vq.Debug {
		for i, e := range data.Write {
			log.Printf("write %d: %q (%d)", i, e, len(e))
		}
	}
	vq.pushQueue(data, n)
	vq.queueNotify()
}
