package sandbox

import (
	"fmt"
	"sync"
)

// daemonPhase is the lifecycle of one sandbox supervisor process. Boot phases
// describe successfully completed ownership transfers: for example,
// daemonGuestPrepared means the supervisor owns every prepared guest resource,
// not merely that preparation has started.
type daemonPhase uint8

const (
	daemonNew daemonPhase = iota
	daemonLoaded
	daemonHostReady
	daemonGuestPrepared
	daemonGuestConnected
	daemonControlReady
	daemonReady
	daemonStopping
	daemonStopped
	daemonFailed
)

func (p daemonPhase) String() string {
	switch p {
	case daemonNew:
		return "new"
	case daemonLoaded:
		return "loaded"
	case daemonHostReady:
		return "host-ready"
	case daemonGuestPrepared:
		return "guest-prepared"
	case daemonGuestConnected:
		return "guest-connected"
	case daemonControlReady:
		return "control-ready"
	case daemonReady:
		return "ready"
	case daemonStopping:
		return "stopping"
	case daemonStopped:
		return "stopped"
	case daemonFailed:
		return "failed"
	default:
		return fmt.Sprintf("daemon-phase-%d", uint8(p))
	}
}

// daemonLifecycle is the supervisor's lifecycle authority. The boot goroutine
// advances the successful path; shutdown may be initiated by that goroutine or
// by a failure path, so stop is idempotent and serialized.
//
// Resource owners remain responsible for their own Close implementation. This
// machine defines when teardown starts and ensures a terminal phase is not
// published until daemonSupervisor.close has completed its process-level teardown
// policy. Graceful device shutdown happens earlier in the stopping phase.
type daemonLifecycle struct {
	mu    sync.RWMutex
	phase daemonPhase
}

func (l *daemonLifecycle) Phase() daemonPhase {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.phase
}

// advance records one completed boot stage. Skipped, repeated, and backwards
// transitions are rejected so readiness cannot accidentally bypass a stage.
func (l *daemonLifecycle) advance(next daemonPhase) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !validDaemonAdvance(l.phase, next) {
		return fmt.Errorf("invalid daemon lifecycle transition %s -> %s", l.phase, next)
	}
	l.phase = next
	return nil
}

func validDaemonAdvance(current, next daemonPhase) bool {
	switch current {
	case daemonNew:
		return next == daemonLoaded
	case daemonLoaded:
		return next == daemonHostReady
	case daemonHostReady:
		return next == daemonGuestPrepared
	case daemonGuestPrepared:
		return next == daemonGuestConnected
	case daemonGuestConnected:
		return next == daemonControlReady
	case daemonControlReady:
		return next == daemonReady
	default:
		return false
	}
}

// beginStop enters the common teardown phase from any live phase. It returns
// true only to the caller which initiated shutdown.
func (l *daemonLifecycle) beginStop() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch l.phase {
	case daemonNew, daemonLoaded, daemonHostReady, daemonGuestPrepared,
		daemonGuestConnected, daemonControlReady, daemonReady:
		l.phase = daemonStopping
		return true
	case daemonStopping, daemonStopped, daemonFailed:
		return false
	default:
		return false
	}
}

// finish publishes the terminal outcome after resource teardown. A successful
// daemon run becomes stopped; every non-zero run becomes failed.
func (l *daemonLifecycle) finish(failed bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.phase != daemonStopping {
		return fmt.Errorf("cannot finish daemon lifecycle from %s", l.phase)
	}
	if failed {
		l.phase = daemonFailed
	} else {
		l.phase = daemonStopped
	}
	return nil
}
