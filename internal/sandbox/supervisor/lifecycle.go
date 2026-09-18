package supervisor

import (
	"fmt"
	"sync"
)

// Phase is the lifecycle of one sandbox supervisor process. Boot phases
// describe successfully completed ownership transfers.
type Phase uint8

const (
	New Phase = iota
	Loaded
	HostReady
	GuestPrepared
	GuestConnected
	ControlReady
	Ready
	Stopping
	Stopped
	Failed
)

func (p Phase) String() string {
	switch p {
	case New:
		return "new"
	case Loaded:
		return "loaded"
	case HostReady:
		return "host-ready"
	case GuestPrepared:
		return "guest-prepared"
	case GuestConnected:
		return "guest-connected"
	case ControlReady:
		return "control-ready"
	case Ready:
		return "ready"
	case Stopping:
		return "stopping"
	case Stopped:
		return "stopped"
	case Failed:
		return "failed"
	default:
		return fmt.Sprintf("daemon-phase-%d", uint8(p))
	}
}

// Lifecycle is the supervisor lifecycle authority. The boot goroutine
// advances the successful path; BeginStop serializes every teardown path.
type Lifecycle struct {
	mu    sync.RWMutex
	phase Phase
}

func (l *Lifecycle) Phase() Phase {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.phase
}

// Advance records one completed boot stage. Skipped, repeated, and backwards
// transitions are rejected.
func (l *Lifecycle) Advance(next Phase) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !validAdvance(l.phase, next) {
		return fmt.Errorf("invalid daemon lifecycle transition %s -> %s", l.phase, next)
	}
	l.phase = next
	return nil
}

func validAdvance(current, next Phase) bool {
	switch current {
	case New:
		return next == Loaded
	case Loaded:
		return next == HostReady
	case HostReady:
		return next == GuestPrepared
	case GuestPrepared:
		return next == GuestConnected
	case GuestConnected:
		return next == ControlReady
	case ControlReady:
		return next == Ready
	default:
		return false
	}
}

// BeginStop enters teardown from any live phase. It returns true only to the
// caller which initiated shutdown.
func (l *Lifecycle) BeginStop() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch l.phase {
	case New, Loaded, HostReady, GuestPrepared, GuestConnected, ControlReady, Ready:
		l.phase = Stopping
		return true
	case Stopping, Stopped, Failed:
		return false
	default:
		return false
	}
}

// Finish publishes the terminal outcome after resource teardown.
func (l *Lifecycle) Finish(failed bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.phase != Stopping {
		return fmt.Errorf("cannot finish daemon lifecycle from %s", l.phase)
	}
	if failed {
		l.phase = Failed
	} else {
		l.phase = Stopped
	}
	return nil
}
