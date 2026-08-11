// Copyright 2024 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vhostuser

import (
	"fmt"
	"sync"
	"syscall"
)

type Device struct {
	reqFD int

	Debug bool

	vqs []*Virtq

	regions  deviceRegions
	logTable []byte

	handle func(*VirtqElem) int

	// dispatchMu guards all control-plane mutations (SET_VRING_*, ADD_MEM_REG,
	// etc.) against concurrent vring dequeue.  Control messages take the write
	// lock; queue threads take the read lock while draining the avail ring.
	// FUSE request processing runs without dispatchMu (matching virtiofsd's
	// vu_dispatch_rwlock design). completionMu orders reverse invalidations
	// after every host operation whose result they may invalidate.
	dispatchMu   sync.RWMutex
	completionMu sync.RWMutex
}

func (d *Device) Close() error {
	var retErr error
	for i := range d.vqs {
		if d.vqs[i].notifications != nil {
			d.vqs[i].notifications.close()
		}
		if err := d.vqs[i].Close(); err != nil && retErr == nil {
			retErr = err
		}
	}

	if err := d.regions.Close(); err != nil && retErr == nil {
		retErr = err
	}

	if d.logTable != nil {
		if err := unmapRegion(d.logTable); err != nil && retErr == nil {
			retErr = err
		}
	}
	return retErr
}

// NewDevice creates the traditional two-queue virtio-fs device.
func NewDevice(handle func(*VirtqElem) int) *Device {
	return NewDeviceWithQueues(2, handle)
}

// NewDeviceWithQueues creates a virtio device with an explicit, bounded queue
// count. Gantry uses a third queue for reverse FUSE invalidations.
func NewDeviceWithQueues(queueCount int, handle func(*VirtqElem) int) *Device {
	if queueCount < 1 || queueCount > 64 {
		panic("vhostuser: invalid queue count")
	}
	d := &Device{vqs: make([]*Virtq, queueCount), handle: handle}
	for i := range d.vqs {
		d.vqs[i] = newVirtq(d)
	}
	return d
}

// SetNotificationQueue parks writable guest buffers on queueIndex and invokes
// ready when the first buffer arrives. Passing nil to ready on shutdown lets
// the owner detach its notification source before shared memory is unmapped.
func (d *Device) SetNotificationQueue(queueIndex int, ready func(func([]byte) syscall.Errno)) error {
	if queueIndex < 0 || queueIndex >= len(d.vqs) {
		return fmt.Errorf("notification queue %d out of range", queueIndex)
	}
	if d.vqs[queueIndex].notifications != nil {
		return fmt.Errorf("notification queue %d already configured", queueIndex)
	}
	d.vqs[queueIndex].notifications = newNotificationQueue(d.vqs[queueIndex], ready)
	return nil
}

// https://qemu-project.gitlab.io/qemu/interop/vhost-user.html#communication
// is incorrect regarding types.
func (d *Device) SetLogBase(fd int, log *VhostUserLog) error {
	data, err := mapSharedRegion(fd, int64(log.MmapOffset), int(log.MmapSize))
	syscall.Close(fd)
	if err != nil {
		return err
	}
	if d.logTable != nil {
		_ = unmapRegion(d.logTable)
	}

	d.logTable = data
	return nil
}

const maxQueueSize = 128

func (d *Device) queue(index uint64) (*Virtq, error) {
	if index >= uint64(len(d.vqs)) {
		return nil, fmt.Errorf("virtqueue index %d out of range", index)
	}
	return d.vqs[index], nil
}

func (d *Device) SetVringAddr(addr *VhostVringAddr) error {
	if addr == nil {
		return fmt.Errorf("nil vring address")
	}
	queue, err := d.queue(uint64(addr.Index))
	if err != nil {
		return err
	}
	return queue.SetVringAddr(addr)
}

func (d *Device) SetVringNum(state *VhostVringState) error {
	if state == nil || state.Num == 0 || state.Num > maxQueueSize {
		return fmt.Errorf("invalid vring size")
	}
	queue, err := d.queue(uint64(state.Index))
	if err != nil {
		return err
	}
	queue.Vring.Num = int(state.Num)
	return nil
}

func (d *Device) SetVringBase(state *VhostVringState) error {
	if state == nil || state.Num > uint32(^uint16(0)) {
		return fmt.Errorf("invalid vring base")
	}
	queue, err := d.queue(uint64(state.Index))
	if err != nil {
		return err
	}
	queue.ShadowAvailIdx = uint16(state.Num)
	queue.LastAvailIdx = uint16(state.Num)
	return nil
}

func (d *Device) SetVringEnable(state *VhostVringState) error {
	if state == nil || state.Num > 1 {
		return fmt.Errorf("invalid vring enable")
	}
	queue, err := d.queue(uint64(state.Index))
	if err != nil {
		return err
	}
	if state.Num != 0 {
		queue.SetEnable(d.handle)
	} else {
		queue.SetEnable(nil)
	}
	return nil
}

type VirtqElem struct {
	// this is the index into Vring.Desc
	index uint

	// read and write from our perspective. The write field is for
	// consumers (ie the file system). We return the total length
	// to the driver, which can find the memory through the vring
	// index above.
	Write [][]byte
	Read  [][]byte
}

func (d *Device) logQueueFill(vq *Virtq, elem *VirtqElem, len int) {
	// NOP, need LOG_SHMFD features
}

// set bit in dev.LogTable bitvector . the bitvector indexes 4k pages
// this lets the guest know there was a write in the page. Needs
// LOG_SHMFD feature.
func (d *Device) logWrite(address, sz uint64) {
	if d.logTable == nil || sz == 0 {
		return
	}

	// if !F_LOG_ALL return
	// mark addr in the d.LogTable bitvector.
	// kick the log fd.
}

// SetVringKick sets the kick eventfd for the virtqueue at index.
//
// The field is frozen once the vring has been enabled: by then a readLoop
// goroutine is blocked on syscall.Read(vq.KickFD) and reassigning the fd
// would be a data race.  The vhost-user protocol orders SET_VRING_KICK
// before SET_VRING_ENABLE, so a well-behaved driver never hits this path
// twice; we reject it explicitly rather than rely on that assumption.
func (d *Device) SetVringKick(fd int, index uint64) error {
	if index&(1<<8) != 0 {
		return fmt.Errorf("invalid vring kick index %#x", index)
	}
	vq, err := d.queue(index)
	if err != nil {
		return err
	}
	if vq.control != nil {
		return fmt.Errorf("SET_VRING_KICK after vring %d enabled", index)
	}
	if old := vq.KickFD; old >= 0 {
		syscall.Close(old)
	}
	vq.KickFD = fd

	// The kick FD is a notification channel, so it must be blocking.
	if err := syscall.SetNonblock(fd, false); err != nil {
		return err
	}
	return nil
}

// SetVringErr sets the error eventfd.
func (d *Device) SetVringErr(fd int, index uint64) error {
	if index&(1<<8) != 0 {
		return fmt.Errorf("invalid vring error index %#x", index)
	}
	queue, err := d.queue(index)
	if err != nil {
		return err
	}
	if old := queue.ErrFD; old >= 0 {
		_ = syscall.Close(old)
	}
	queue.ErrFD = fd
	return nil
}

// SetVringCall sets the call eventfd.
func (d *Device) SetVringCall(fd int, index uint64) error {
	if index&(1<<8) != 0 {
		return fmt.Errorf("invalid vring call index %#x", index)
	}
	queue, err := d.queue(index)
	if err != nil {
		return err
	}
	if old := queue.CallFD; old >= 0 {
		_ = syscall.Close(old)
	}
	queue.CallFD = fd
	return nil
}

func (d *Device) SetOwner() {

}

func (d *Device) SetReqFD(fd int) {
	d.reqFD = fd
}

func (d *Device) GetQueueNum() uint64 {
	return uint64(len(d.vqs))
}

func (h *Device) GetFeatures() []int {
	return []int{
		// Device-specific bit 23 is VIRTIO_FS_F_GANTRY_NOTIFICATION.
		23,
		RING_F_INDIRECT_DESC,
		RING_F_EVENT_IDX,
		F_PROTOCOL_FEATURES,
		F_VERSION_1,
	}
}

func (h *Device) SetFeatures(features []int) {
	eventIdx := false
	for _, feature := range features {
		if feature == RING_F_EVENT_IDX {
			eventIdx = true
			break
		}
	}
	for _, queue := range h.vqs {
		queue.EventIdx = eventIdx
	}
}

func (h *Device) SetProtocolFeatures([]int) {

}

func (h *Device) GetProtocolFeatures() []int {
	// not supporting VHOST_USER_PROTOCOL_F_PAGEFAULT, so no support for
	// postcopy listening.

	// NOTE: PROTOCOL_F_LOG_SHMFD is not advertised here, but SetLogBase is
	// implemented and reachable.  Either advertise the feature or remove the
	// handler.

	// ")\204\0\0\0\0\0\0"
	// x29 x84
	return []int{
		PROTOCOL_F_MQ,
		PROTOCOL_F_REPLY_ACK,
		PROTOCOL_F_BACKEND_REQ,
		PROTOCOL_F_BACKEND_SEND_FD,
		PROTOCOL_F_CONFIGURE_MEM_SLOTS,
	}
}
