// Package exportstate owns the lifecycle phase of one sharefs export without
// depending on filesystem nodes, host handles, or the parent sharefs package.
package exportstate

import "sync/atomic"

type Phase int32

const (
	Active Phase = iota
	Draining
	Revoked
	Gone
)

func (phase Phase) String() string {
	switch phase {
	case Active:
		return "active"
	case Draining:
		return "draining"
	case Revoked:
		return "revoked"
	default:
		return "gone"
	}
}

func ValidTransition(current, next Phase) bool {
	switch current {
	case Active:
		return next == Draining || next == Revoked
	case Draining:
		return next == Revoked
	case Revoked:
		return next == Gone
	default:
		return false
	}
}

// Owner is the single writer for an export phase. Its zero value is Active.
type Owner struct{ phase atomic.Int32 }

func (owner *Owner) Phase() Phase {
	if owner == nil {
		return Gone
	}
	return Phase(owner.phase.Load())
}

// Transition validates a monotonic ownership transfer. Repeating the current
// phase is idempotent; stale transitions cannot regress or skip release phases.
func (owner *Owner) Transition(next Phase) bool {
	if owner == nil {
		return false
	}
	for {
		current := Phase(owner.phase.Load())
		if current == next {
			return true
		}
		if !ValidTransition(current, next) {
			return false
		}
		if owner.phase.CompareAndSwap(int32(current), int32(next)) {
			return true
		}
	}
}
