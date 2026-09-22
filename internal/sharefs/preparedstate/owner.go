// Package preparedstate owns the single-use lifecycle of a prepared share.
// It is independent of host handles and the parent sharefs package.
package preparedstate

import "sync"

type Phase uint8

const (
	Prepared Phase = iota
	InUse
	Closing
	Consumed
	Closed
)

// Lease authorizes one publication attempt. Its generation rejects stale or
// duplicate completion if a failed attempt returns ownership to Prepared.
type Lease struct{ generation uint64 }

// Owner serializes publication, inspection, and close. Its zero value is a
// prepared owner.
type Owner struct {
	mu         sync.Mutex
	cond       *sync.Cond
	phase      Phase
	generation uint64
	done       chan struct{}
}

func (owner *Owner) initLocked() {
	if owner.cond == nil {
		owner.cond = sync.NewCond(&owner.mu)
	}
}

func (owner *Owner) Phase() Phase {
	if owner == nil {
		return Closed
	}
	owner.mu.Lock()
	phase := owner.phase
	owner.mu.Unlock()
	return phase
}

// Acquire waits for an earlier attempt and claims the prepared capability. It
// returns false after another caller consumes or closes that capability.
func (owner *Owner) Acquire() (Lease, bool) {
	if owner == nil {
		return Lease{}, false
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owner.initLocked()
	for owner.phase == InUse {
		owner.cond.Wait()
	}
	if owner.phase != Prepared {
		return Lease{}, false
	}
	owner.generation++
	lease := Lease{generation: owner.generation}
	owner.phase = InUse
	return lease, true
}

// Complete returns ownership after a failed attempt or permanently transfers
// it after successful publication.
func (owner *Owner) Complete(lease Lease, consumed bool) bool {
	if owner == nil {
		return false
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owner.initLocked()
	if owner.phase != InUse || lease.generation == 0 || lease.generation != owner.generation {
		return false
	}
	if consumed {
		owner.phase = Consumed
		owner.closeDoneLocked()
	} else {
		owner.phase = Prepared
	}
	owner.cond.Broadcast()
	return true
}

// BeginClose waits for an active publication attempt. Exactly one caller owns
// resource release; duplicate callers join its completion channel.
func (owner *Owner) BeginClose() (leader bool, done <-chan struct{}) {
	if owner == nil {
		closed := make(chan struct{})
		close(closed)
		return false, closed
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owner.initLocked()
	for owner.phase == InUse {
		owner.cond.Wait()
	}
	if owner.done == nil {
		owner.done = make(chan struct{})
	}
	switch owner.phase {
	case Prepared:
		owner.phase = Closing
		return true, owner.done
	case Closing:
		return false, owner.done
	case Consumed:
		owner.closeDoneLocked()
		return false, owner.done
	case Closed:
		return false, owner.done
	default:
		return false, owner.done
	}
}

func (owner *Owner) FinishClose() bool {
	if owner == nil {
		return false
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.phase != Closing {
		return false
	}
	owner.phase = Closed
	owner.closeDoneLocked()
	owner.cond.Broadcast()
	return true
}

func (owner *Owner) closeDoneLocked() {
	if owner.done == nil {
		owner.done = make(chan struct{})
	}
	select {
	case <-owner.done:
	default:
		close(owner.done)
	}
}
