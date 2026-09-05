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

	ready          func(func([]byte) syscall.Errno)
	attached       bool
	closed         bool
	flushScheduled bool
	slots          []*VirtqElem
	pending        [][]byte
	bytes          int
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
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return syscall.EIO
	}
	if len(q.pending) >= maxPendingNotifications ||
		q.bytes+len(copyOfMessage) > maxPendingNotificationBytes {
		q.mu.Unlock()
		return syscall.EAGAIN
	}
	q.pending = append(q.pending, copyOfMessage)
	q.bytes += len(copyOfMessage)
	startFlush := !q.flushScheduled
	if startFlush {
		q.flushScheduled = true
	}
	q.mu.Unlock()

	// A FUSE handler can synchronously emit a notification (notably the node
	// budget's PRUNE request). Request processing holds completionMu.RLock so
	// that notifications become visible only after the operation they
	// invalidate. Acquiring completionMu.Lock here would make that handler wait
	// for its own read lock forever. Defer delivery to a goroutine: it waits for
	// the request completion and preserves the same ordering without recursion.
	if startFlush {
		go q.flush()
	}
	return 0
}

func (q *notificationQueue) flush() {
	q.vq.completionMu.Lock()
	defer q.vq.completionMu.Unlock()
	q.mu.Lock()
	if !q.closed {
		q.flushLocked()
	}
	q.flushScheduled = false
	q.mu.Unlock()
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

// reset detaches the notification source and discards buffers owned by the
// old virtqueue generation. The caller has already stopped the queue reader
// and joined ordinary requests; completionMu also joins a scheduled flush.
func (q *notificationQueue) reset() {
	if q == nil {
		return
	}
	q.vq.completionMu.Lock()
	q.mu.Lock()
	q.closed = true
	detach := q.attached
	q.attached = false
	q.slots = nil
	q.pending = nil
	q.bytes = 0
	q.flushScheduled = false
	q.mu.Unlock()
	q.vq.completionMu.Unlock()
	if detach && q.ready != nil {
		q.ready(nil)
	}
	q.mu.Lock()
	q.closed = false
	q.mu.Unlock()
}
