package virtio

// pendingRing is the fixed-capacity queue used by asynchronous device
// producers. Its storage is part of the device, so rejecting an item from a
// full queue never allocates. Pop clears the vacated slot immediately; this is
// important for packet payloads, whose backing arrays can otherwise remain
// reachable until the ring wraps.
//
// The virtio-net and virtio-vsock receive paths deliberately share the same
// bound. Keeping the capacity a power of two also makes the hot wraparound
// operations cheap, although the explicit branch is clear enough for the
// compiler to optimize without bit tricks here.
const pendingRingCapacity = 256

type pendingRing[T any] struct {
	slots [pendingRingCapacity]T
	head  int
	count int
}

func (q *pendingRing[T]) Len() int   { return q.count }
func (q *pendingRing[T]) Full() bool { return q.count == len(q.slots) }

// Push appends value and returns its stable slot index. The index remains
// valid until the value reaches the front and is popped.
func (q *pendingRing[T]) Push(value T) (int, bool) {
	if q.Full() {
		return 0, false
	}
	tail := q.head + q.count
	if tail >= len(q.slots) {
		tail -= len(q.slots)
	}
	q.slots[tail] = value
	q.count++
	return tail, true
}

func (q *pendingRing[T]) Front() (*T, int, bool) {
	if q.count == 0 {
		return nil, 0, false
	}
	return &q.slots[q.head], q.head, true
}

// Back returns the most recently pushed item.
func (q *pendingRing[T]) Back() (*T, int, bool) {
	if q.count == 0 {
		return nil, 0, false
	}
	tail := q.head + q.count - 1
	if tail >= len(q.slots) {
		tail -= len(q.slots)
	}
	return &q.slots[tail], tail, true
}

func (q *pendingRing[T]) Pop() {
	if q.count == 0 {
		return
	}
	var zero T
	q.slots[q.head] = zero
	q.head++
	if q.head == len(q.slots) {
		q.head = 0
	}
	q.count--
}

func (q *pendingRing[T]) Reset() {
	for q.count != 0 {
		q.Pop()
	}
	q.head = 0
}
