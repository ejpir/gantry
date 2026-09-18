package sandbox

import (
	"context"
	"net"
	"sync"
)

type sshGatewayPhase uint8

const (
	sshGatewayIdle sshGatewayPhase = iota
	sshGatewayRunning
	sshGatewayStopping
)

// sshGatewayOwner is the sole owner of the live SSH listener and its serving
// generation. start transfers listener ownership on success; stop prevents a
// concurrent replacement and joins every goroutine through backgroundGroup.
type sshGatewayOwner struct {
	mu       sync.Mutex
	phase    sshGatewayPhase
	listener net.Listener
	workers  *backgroundGroup
}

func (o *sshGatewayOwner) running() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.phase == sshGatewayRunning
}

// start consumes listener when it returns true. A false result means another
// gateway is already active and the caller retains ownership of listener.
func (o *sshGatewayOwner) start(listener net.Listener, serve func(context.Context, net.Listener)) bool {
	if listener == nil || serve == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.phase != sshGatewayIdle {
		return false
	}
	workers := new(backgroundGroup)
	if !workers.start(func(ctx context.Context) { serve(ctx, listener) }) {
		return false
	}
	o.phase = sshGatewayRunning
	o.listener = listener
	o.workers = workers
	return true
}

func (o *sshGatewayOwner) stop() {
	o.mu.Lock()
	switch o.phase {
	case sshGatewayIdle:
		o.mu.Unlock()
		return
	case sshGatewayStopping:
		workers := o.workers
		o.mu.Unlock()
		if workers != nil {
			workers.close()
		}
		return
	case sshGatewayRunning:
		o.phase = sshGatewayStopping
	}
	listener, workers := o.listener, o.workers
	o.listener = nil
	o.mu.Unlock()

	if listener != nil {
		_ = listener.Close()
	}
	if workers != nil {
		workers.close()
	}

	o.mu.Lock()
	if o.phase == sshGatewayStopping {
		o.phase = sshGatewayIdle
		o.workers = nil
	}
	o.mu.Unlock()
}
