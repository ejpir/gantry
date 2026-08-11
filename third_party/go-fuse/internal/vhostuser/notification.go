package vhostuser

import (
	"sync"
	"syscall"
)

const (
	maxNotificationBytes        = 8 << 10
	maxPendingNotifications     = 70 << 10
	maxPendingNotificationBytes = 8 << 20
)

type notificationQueue struct {
	mu sync.Mutex
	vq *Virtq

	ready    func(func([]byte) syscall.Errno)
	attached bool
	closed   bool
	slots    []*VirtqElem
	pending  [][]byte
	bytes    int
}

func newNotificationQueue(vq *Virtq, ready func(func([]byte) syscall.Errno)) *notificationQueue {
	return &notificationQueue{vq: vq, ready: ready}
}

func (q *notificationQueue) add(elem *VirtqElem) {
	if q == nil || elem == nil {
		return
	}
	q.vq.completionMu.Lock()
	defer q.vq.completionMu.Unlock()
	capacity := 0
	for _, part := range elem.Write {
		capacity += len(part)
	}
	if len(elem.Read) != 0 || capacity == 0 || capacity > maxNotificationBytes {
		q.vq.pushQueue(elem, 0)
		q.vq.queueNotify()
		return
	}
	q.mu.Lock()
	if q.closed || len(q.slots) >= maxQueueSize {
		q.mu.Unlock()
		q.vq.pushQueue(elem, 0)
		q.vq.queueNotify()
		return
	}
	q.slots = append(q.slots, elem)
	attach := !q.attached && q.ready != nil
	if attach {
		q.attached = true
	}
	q.flushLocked()
	q.mu.Unlock()
	if attach {
		q.ready(q.enqueue)
	}
}

func (q *notificationQueue) enqueue(message []byte) syscall.Errno {
	if q == nil || len(message) == 0 || len(message) > maxNotificationBytes {
		return syscall.EINVAL
	}
	copyOfMessage := append([]byte(nil), message...)
	q.vq.completionMu.Lock()
	defer q.vq.completionMu.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return syscall.EIO
	}
	if len(q.pending) >= maxPendingNotifications ||
		q.bytes+len(copyOfMessage) > maxPendingNotificationBytes {
		return syscall.EAGAIN
	}
	q.pending = append(q.pending, copyOfMessage)
	q.bytes += len(copyOfMessage)
	q.flushLocked()
	return 0
}

func (q *notificationQueue) flushLocked() {
	completed := false
	for len(q.pending) != 0 && len(q.slots) != 0 {
		message := q.pending[0]
		elem := q.slots[0]
		q.pending[0] = nil
		q.pending = q.pending[1:]
		q.slots[0] = nil
		q.slots = q.slots[1:]
		q.bytes -= len(message)
		written := scatterNotification(elem.Write, message)
		q.vq.pushQueue(elem, written)
		completed = true
	}
	if completed {
		q.vq.queueNotify()
	}
	if len(q.pending) == 0 {
		q.pending = nil
	}
	if len(q.slots) == 0 {
		q.slots = nil
	}
}

func scatterNotification(iov [][]byte, message []byte) int {
	written := 0
	for _, part := range iov {
		if written == len(message) {
			break
		}
		written += copy(part, message[written:])
	}
	if written != len(message) {
		return 0
	}
	return written
}

func (q *notificationQueue) close() {
	if q == nil {
		return
	}
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.closed = true
	detach := q.attached
	q.attached = false
	q.slots = nil
	q.pending = nil
	q.bytes = 0
	q.mu.Unlock()
	if detach && q.ready != nil {
		q.ready(nil)
	}
}
