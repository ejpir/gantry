//go:build linux || darwin || windows

package virtio

import (
	"fmt"
	"os"
	"sync"

	"github.com/ejpir/gantry/internal/fusewire"

	"github.com/hanwen/go-fuse/v2/fuse"
)

const (
	// VIRTIO_FS_F_GANTRY_NOTIFICATION is negotiated only with Gantry's owned
	// guest kernel. It adds one device-to-driver queue after the standard
	// hiprio and request queues.
	virtioFSFGantryNotification = uint64(1 << 23)
	virtioFSNotificationQ       = 2
	virtioFSQueueCount          = 3

	maxPendingFSNotifications     = 70 << 10
	maxPendingFSNotificationBytes = 8 << 20
)

type fsNotificationSlot struct {
	head uint16
	desc desc
}

type fsNotificationQueue struct {
	mu sync.Mutex

	core   *Core
	source fusewire.NotificationSource
	debug  bool

	attached bool
	closed   bool
	// A notification may be emitted synchronously by a FUSE request handler.
	// That handler runs under Core.mu, so delivery must be deferred until the
	// MMIO request returns instead of trying to acquire Core.mu recursively.
	flushScheduled bool
	slots          []fsNotificationSlot
	pending        [][]byte
	bytes          int
}

func newFSNotificationQueue(core *Core, source fusewire.NotificationSource) *fsNotificationQueue {
	return &fsNotificationQueue{
		core:   core,
		source: source,
		debug:  os.Getenv("GANTRY_DEBUG_FS") != "",
	}
}

// acceptAvailable is called with Core.mu held.
func (q *fsNotificationQueue) acceptAvailable() {
	if q == nil || q.core == nil {
		return
	}
	queue := &q.core.queues[virtioFSNotificationQ]
	q.mu.Lock()
	for {
		head, chain, ok := q.core.availChain(virtioFSNotificationQ)
		if !ok {
			break
		}
		readable, writable := splitChain(chain)
		if len(readable) != 0 || len(writable) != 1 || writable[0].len == 0 ||
			writable[0].len > fusewire.MaxNotificationBytes || len(q.slots) >= virtqSize {
			q.core.pushUsed(queue, head, 0)
			continue
		}
		q.slots = append(q.slots, fsNotificationSlot{head: head, desc: writable[0]})
	}
	q.flushLocked(queue)
	attach := !q.closed && !q.attached && q.source != nil && len(q.slots) != 0
	if attach {
		q.attached = true
	}
	q.mu.Unlock()
	if attach {
		q.source.SetNotificationSink(q.enqueue)
	}
}

func (q *fsNotificationQueue) enqueue(message []byte) fuse.Status {
	if q == nil || !fusewire.ValidNotification(message) {
		return fuse.EINVAL
	}
	copyOfMessage := append([]byte(nil), message...)
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return fuse.EIO
	}
	if len(q.pending) >= maxPendingFSNotifications ||
		q.bytes+len(copyOfMessage) > maxPendingFSNotificationBytes {
		q.mu.Unlock()
		return fuse.EAGAIN
	}
	q.pending = append(q.pending, copyOfMessage)
	q.bytes += len(copyOfMessage)
	startFlush := !q.flushScheduled
	if startFlush {
		q.flushScheduled = true
	}
	q.mu.Unlock()

	if startFlush {
		go q.flush()
	}
	return fuse.OK
}

// flush acquires Core.mu only after the notification source has returned to
// its caller. FUSE handlers can therefore enqueue reverse notifications while
// Core.MMIOWrite is dispatching a request without self-deadlocking the vCPU.
// flushScheduled bounds this to one delivery goroutine per pending burst.
func (q *fsNotificationQueue) flush() {
	q.core.mu.Lock()
	q.mu.Lock()
	pendingBefore := len(q.pending)
	slotsBefore := len(q.slots)
	if !q.closed {
		q.flushLocked(&q.core.queues[virtioFSNotificationQ])
	}
	if q.debug {
		fmt.Fprintf(os.Stderr, "virtio-fs: notification flush: delivered=%d pending=%d slots=%d (before=%d/%d)\n",
			pendingBefore-len(q.pending), len(q.pending), len(q.slots), pendingBefore, slotsBefore)
	}
	q.flushScheduled = false
	q.mu.Unlock()
	q.core.mu.Unlock()
}

// flushLocked requires both Core.mu and q.mu.
func (q *fsNotificationQueue) flushLocked(queue *virtq) {
	for len(q.pending) != 0 && len(q.slots) != 0 {
		message := q.pending[0]
		slot := q.slots[0]
		q.pending[0] = nil
		q.pending = q.pending[1:]
		q.slots = q.slots[1:]
		q.bytes -= len(message)
		written := uint32(0)
		if uint32(len(message)) <= slot.desc.len && q.core.mem.writeAt(slot.desc.addr, message) == nil {
			written = uint32(len(message))
		}
		q.core.pushUsed(queue, slot.head, written)
	}
	if len(q.pending) == 0 {
		q.pending = nil
	}
	if len(q.slots) == 0 {
		q.slots = nil
	}
}

// reset is called with Core.mu held.
func (q *fsNotificationQueue) reset() {
	if q == nil {
		return
	}
	q.mu.Lock()
	detach := q.attached
	q.attached = false
	q.closed = false
	q.slots = nil
	q.pending = nil
	q.bytes = 0
	q.mu.Unlock()
	if detach && q.source != nil {
		q.source.SetNotificationSink(nil)
	}
}

func (q *fsNotificationQueue) close() {
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
	if detach && q.source != nil {
		q.source.SetNotificationSink(nil)
	}
}
