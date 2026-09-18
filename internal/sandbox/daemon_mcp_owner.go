package sandbox

import (
	"context"
	"net"
	"sync"

	"github.com/ejpir/gantry/internal/workerconf"
)

type mcpGatewayPhase uint8

const (
	mcpGatewayIdle mcpGatewayPhase = iota
	mcpGatewayRunning
	mcpGatewayStopping
	mcpGatewayExited
	mcpGatewayClosed
)

type mcpGatewayWorker interface {
	Serve(context.Context, net.Conn) error
	Done() <-chan struct{}
	ConfinementReport() *workerconf.Report
	CloseSessions()
	Close() error
}

// mcpGatewayOwner owns the MCP listener, confined worker, accept loop, worker
// watcher, and every accepted relay goroutine. backgroundGroup serializes task
// admission against shutdown and joins all callbacks which borrow daemon
// services before close returns.
type mcpGatewayOwner struct {
	mu       sync.Mutex
	phase    mcpGatewayPhase
	listener net.Listener
	worker   mcpGatewayWorker
	workers  *backgroundGroup
	closed   chan struct{}
}

func (o *mcpGatewayOwner) start(listener net.Listener, worker mcpGatewayWorker, sessionError, workerExit func()) bool {
	if listener == nil || worker == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.phase != mcpGatewayIdle {
		return false
	}
	workers := new(backgroundGroup)
	o.phase = mcpGatewayRunning
	o.listener = listener
	o.worker = worker
	o.workers = workers
	o.closed = make(chan struct{})
	workers.start(func(ctx context.Context) { o.accept(ctx, listener, worker, sessionError) })
	workers.start(func(ctx context.Context) { o.watch(ctx, worker, listener, workerExit) })
	return true
}

func (o *mcpGatewayOwner) accept(ctx context.Context, listener net.Listener, worker mcpGatewayWorker, sessionError func()) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		o.mu.Lock()
		running := o.phase == mcpGatewayRunning
		workers := o.workers
		o.mu.Unlock()
		if !running || workers == nil {
			_ = conn.Close()
			return
		}
		if !workers.start(func(ctx context.Context) {
			defer func() { _ = conn.Close() }()
			if err := worker.Serve(ctx, conn); err != nil {
				select {
				case <-worker.Done():
				default:
					if sessionError != nil {
						sessionError()
					}
				}
			}
		}) {
			_ = conn.Close()
			return
		}
	}
}

func (o *mcpGatewayOwner) watch(ctx context.Context, worker mcpGatewayWorker, listener net.Listener, workerExit func()) {
	select {
	case <-worker.Done():
	case <-ctx.Done():
		return
	}
	_ = listener.Close()
	o.mu.Lock()
	if o.phase == mcpGatewayRunning {
		o.phase = mcpGatewayExited
	}
	o.mu.Unlock()
	if workerExit != nil {
		workerExit()
	}
}

func (o *mcpGatewayOwner) closeSessions() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.phase == mcpGatewayRunning && o.worker != nil {
		o.worker.CloseSessions()
	}
}

func (o *mcpGatewayOwner) confinementReport() (*workerconf.Report, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.phase != mcpGatewayRunning || o.worker == nil {
		return nil, false
	}
	select {
	case <-o.worker.Done():
		return nil, false
	default:
		return o.worker.ConfinementReport(), true
	}
}

func (o *mcpGatewayOwner) close() error {
	o.mu.Lock()
	switch o.phase {
	case mcpGatewayIdle, mcpGatewayClosed:
		o.mu.Unlock()
		return nil
	case mcpGatewayStopping:
		closed := o.closed
		o.mu.Unlock()
		if closed != nil {
			<-closed
		}
		return nil
	case mcpGatewayRunning, mcpGatewayExited:
		o.phase = mcpGatewayStopping
	}
	listener, worker, workers := o.listener, o.worker, o.workers
	o.mu.Unlock()

	if listener != nil {
		_ = listener.Close()
	}
	var err error
	if worker != nil {
		err = worker.Close()
	}
	if workers != nil {
		workers.close()
	}

	o.mu.Lock()
	o.listener = nil
	o.worker = nil
	o.workers = nil
	o.phase = mcpGatewayClosed
	if o.closed != nil {
		close(o.closed)
		o.closed = nil
	}
	o.mu.Unlock()
	return err
}
