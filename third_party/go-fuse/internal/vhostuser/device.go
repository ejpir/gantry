// Copyright 2024 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vhostuser

import (
	"fmt"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

type Device struct {
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

func validateDoorbellFD(fd int, write bool) error {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect doorbell fd: %w", err)
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFIFO {
		return fmt.Errorf("doorbell fd is not a pipe")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("inspect doorbell access mode: %w", err)
	}
	access := flags & unix.O_ACCMODE
	if write && access == unix.O_RDONLY {
		return fmt.Errorf("call doorbell fd is not writable")
	}
	if !write && access == unix.O_WRONLY {
		return fmt.Errorf("kick doorbell fd is not readable")
	}
	return nil
}

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
	if queue.Vring.Initialized() && queue.Addr == *addr {
		return nil
	}
	if queue.control != nil {
		return fmt.Errorf("SET_VRING_ADDR after vring %d enabled", addr.Index)
	}
	if queue.Vring.Initialized() {
		return fmt.Errorf("SET_VRING_ADDR cannot relocate mapped vring %d", addr.Index)
	}
	return queue.SetVringAddr(addr)
}

func (d *Device) SetVringNum(state *VhostVringState) error {
	if state == nil || state.Num == 0 || state.Num > maxQueueSize || state.Num&(state.Num-1) != 0 {
		return fmt.Errorf("invalid vring size")
	}
	queue, err := d.queue(uint64(state.Index))
	if err != nil {
		return err
	}
	if queue.Vring.Num == int(state.Num) {
		return nil
	}
	if queue.control != nil {
		return fmt.Errorf("SET_VRING_NUM after vring %d enabled", state.Index)
	}
	if queue.Vring.Initialized() && queue.Vring.Num != int(state.Num) {
		return fmt.Errorf("SET_VRING_NUM cannot resize mapped vring %d", state.Index)
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
	if queue.ShadowAvailIdx == uint16(state.Num) && queue.LastAvailIdx == uint16(state.Num) {
		return nil
	}
	if queue.control != nil {
		return fmt.Errorf("SET_VRING_BASE after vring %d enabled", state.Index)
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
	queue.lifecycleMu.Lock()
	defer queue.lifecycleMu.Unlock()
	if state.Num == 0 {
		d.dispatchMu.Lock()
		control := queue.control
		if control == nil {
			queue.Enable = 0
			d.dispatchMu.Unlock()
			return nil
		}
		close(control.cancel)
		d.dispatchMu.Unlock()

		// Never wait while holding dispatchMu: a reader may already be
		// finishing popBatch under its read side. Once done closes, no new
		// request owner can enter the queue.
		<-control.done
		queue.requests.Wait()
		if queue.notifications != nil {
			queue.notifications.reset()
		}

		d.dispatchMu.Lock()
		defer d.dispatchMu.Unlock()
		if queue.control != control {
			return fmt.Errorf("vring %d lifecycle changed during disable", state.Index)
		}
		queue.control = nil
		queue.resetRing()
		return nil
	}

	d.dispatchMu.Lock()
	defer d.dispatchMu.Unlock()
	if queue.control != nil {
		return nil // Idempotent enable.
	}
	if !queue.Vring.Initialized() || queue.Vring.Num == 0 {
		return fmt.Errorf("vring %d is not mapped", state.Index)
	}
	if queue.KickFD < 0 || queue.CallFD < 0 {
		return fmt.Errorf("vring %d doorbells are incomplete", state.Index)
	}
	queue.start(d.handle)
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
// The field is frozen once the vring has been enabled: by then readLoop owns
// the fd and reassigning it would be a data race. The vhost-user protocol
// orders SET_VRING_KICK before SET_VRING_ENABLE, so a well-behaved driver never
// hits this path twice; we reject it explicitly rather than rely on that
// assumption.
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
	if err := validateDoorbellFD(fd, false); err != nil {
		return err
	}
	// Keep the kick descriptor nonblocking. The reader waits with poll so
	// shutdown can observe its cancellation channel even if the peer keeps the
	// write end open forever. The server closes fd when this setter errors.
	if err := syscall.SetNonblock(fd, true); err != nil {
		return err
	}
	if old := vq.KickFD; old >= 0 {
		syscall.Close(old)
	}
	vq.KickFD = fd
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
	if queue.control != nil {
		return fmt.Errorf("SET_VRING_ERR after vring %d enabled", index)
	}
	if err := validateDoorbellFD(fd, true); err != nil {
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
	if queue.control != nil {
		return fmt.Errorf("SET_VRING_CALL after vring %d enabled", index)
	}
	if err := validateDoorbellFD(fd, true); err != nil {
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
		// Completions consult EventIdx outside dispatchMu, so synchronize the
		// negotiated bit with vringNotify's queue lock as well.
		queue.mu.Lock()
		queue.EventIdx = eventIdx
		queue.mu.Unlock()
	}
}

func (h *Device) SetProtocolFeatures([]int) {

}

func (h *Device) GetProtocolFeatures() []int {
	// not supporting VHOST_USER_PROTOCOL_F_PAGEFAULT, so no support for
	// postcopy listening.

	// ")\204\0\0\0\0\0\0"
	// x29 x84
	return []int{
		PROTOCOL_F_MQ,
		PROTOCOL_F_REPLY_ACK,
		PROTOCOL_F_CONFIGURE_MEM_SLOTS,
	}
}
