package sshgw

import (
	"context"
	"net"
	"sync"

	"github.com/ejpir/gantry/internal/sandbox/supervisor"
)

type ownerPhase uint8

const (
	ownerIdle ownerPhase = iota
	ownerRunning
	ownerStopping
)

// Owner owns one live SSH listener and its serving generation. Start transfers
// listener ownership on success; Stop prevents replacement and joins every
// goroutine before returning.
type Owner struct {
	mu       sync.Mutex
	phase    ownerPhase
	listener net.Listener
	workers  *supervisor.BackgroundGroup
}

func (o *Owner) Running() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.phase == ownerRunning
}

// Start consumes listener when it returns true. A false result means another
// gateway is active and the caller retains listener ownership.
func (o *Owner) Start(listener net.Listener, serve func(context.Context, net.Listener)) bool {
	if listener == nil || serve == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.phase != ownerIdle {
		return false
	}
	workers := new(supervisor.BackgroundGroup)
	if !workers.Start(func(ctx context.Context) { serve(ctx, listener) }) {
		return false
	}
	o.phase = ownerRunning
	o.listener = listener
	o.workers = workers
	return true
}

func (o *Owner) Stop() {
	o.mu.Lock()
	switch o.phase {
	case ownerIdle:
		o.mu.Unlock()
		return
	case ownerStopping:
		workers := o.workers
		o.mu.Unlock()
		if workers != nil {
			workers.Close()
		}
		return
	case ownerRunning:
		o.phase = ownerStopping
	}
	listener, workers := o.listener, o.workers
	o.listener = nil
	o.mu.Unlock()

	if listener != nil {
		_ = listener.Close()
	}
	if workers != nil {
		workers.Close()
	}

	o.mu.Lock()
	if o.phase == ownerStopping {
		o.phase = ownerIdle
		o.workers = nil
	}
	o.mu.Unlock()
}
