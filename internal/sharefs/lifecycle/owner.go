// Package lifecycle owns the serving lifetime shared by sharefs hubs and
// standalone servers. It has no dependency on filesystem or transport types.
package lifecycle

import "sync"

// Phase describes whether a sharefs endpoint admits requests.
type Phase uint8

const (
	Active Phase = iota
	Stopping
	Closed
)

// Owner serializes shutdown and lets duplicate callers join the first close.
// Its zero value is an active owner.
type Owner struct {
	mu    sync.Mutex
	phase Phase
	done  chan struct{}
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

// BeginClose transfers shutdown authority to exactly one caller. Other callers
// receive the same completion channel and must wait for the owner to close it.
func (owner *Owner) BeginClose() (leader bool, done <-chan struct{}) {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.done == nil {
		owner.done = make(chan struct{})
	}
	switch owner.phase {
	case Active:
		owner.phase = Stopping
		return true, owner.done
	case Stopping, Closed:
		return false, owner.done
	default:
		return false, owner.done
	}
}

// FinishClose publishes the terminal phase. Only the shutdown leader may call
// it after all borrowers and owned background work have stopped.
func (owner *Owner) FinishClose() bool {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.phase != Stopping {
		return false
	}
	owner.phase = Closed
	close(owner.done)
	return true
}
