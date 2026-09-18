// Package coherencestate owns the cache-coherence watcher phase without
// depending on FUSE nodes or platform watcher implementations.
package coherencestate

import (
	"sync"
	"sync/atomic"
)

type Phase uint32

const (
	Initializing Phase = iota
	Healthy
	Degraded
	Closing
	Closed
)

// Owner is the single writer for coherence health. Its zero value is the
// constructor-only Initializing phase.
type Owner struct {
	phase atomic.Uint32

	closeMu sync.Mutex
	done    chan struct{}
}

func (owner *Owner) Phase() Phase {
	if owner == nil {
		return Closed
	}
	return Phase(owner.phase.Load())
}

func (owner *Owner) Healthy() bool { return owner.Phase() == Healthy }

func (owner *Owner) Activate() bool {
	return owner != nil && owner.phase.CompareAndSwap(uint32(Initializing), uint32(Healthy))
}

// Degrade fails cache coherence closed. It reports whether this caller
// performed the transition and therefore owns any required cache flush.
func (owner *Owner) Degrade() bool {
	if owner == nil {
		return false
	}
	for {
		current := Phase(owner.phase.Load())
		switch current {
		case Initializing, Healthy:
			if owner.phase.CompareAndSwap(uint32(current), uint32(Degraded)) {
				return true
			}
		case Degraded, Closing, Closed:
			return false
		default:
			return false
		}
	}
}

// BeginClose transfers final watcher and cache release to one caller. Other
// callers receive the same completion channel and join that release.
func (owner *Owner) BeginClose() (leader bool, done <-chan struct{}) {
	owner.closeMu.Lock()
	defer owner.closeMu.Unlock()
	if owner.done == nil {
		owner.done = make(chan struct{})
	}
	for {
		current := Phase(owner.phase.Load())
		switch current {
		case Initializing, Healthy, Degraded:
			if owner.phase.CompareAndSwap(uint32(current), uint32(Closing)) {
				return true, owner.done
			}
		case Closing, Closed:
			return false, owner.done
		default:
			return false, owner.done
		}
	}
}

func (owner *Owner) FinishClose() bool {
	owner.closeMu.Lock()
	defer owner.closeMu.Unlock()
	if owner.Phase() != Closing {
		return false
	}
	owner.phase.Store(uint32(Closed))
	close(owner.done)
	return true
}
