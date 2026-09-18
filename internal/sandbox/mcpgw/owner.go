package mcpgw

import (
	"context"
	"net"
	"sync"

	"github.com/ejpir/gantry/internal/sandbox/supervisor"
	"github.com/ejpir/gantry/internal/workerconf"
)

type ownerPhase uint8

const (
	ownerIdle ownerPhase = iota
	ownerRunning
	ownerStopping
	ownerExited
	ownerClosed
)

// Worker is the owned MCP worker capability. Close remains on the ownership
// interface and is never exposed by Owner's borrowed methods.
type Worker interface {
	Serve(context.Context, net.Conn) error
	Done() <-chan struct{}
	ConfinementReport() *workerconf.Report
	CloseSessions()
	Close() error
}

// Owner owns the MCP listener, confined worker, accept loop, worker watcher,
// and every accepted relay goroutine.
type Owner struct {
	mu       sync.Mutex
	phase    ownerPhase
	listener net.Listener
	worker   Worker
	workers  *supervisor.BackgroundGroup
	closed   chan struct{}
}

func (o *Owner) Start(listener net.Listener, worker Worker, sessionError, workerExit func()) bool {
	if listener == nil || worker == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.phase != ownerIdle {
		return false
	}
	workers := new(supervisor.BackgroundGroup)
	o.phase = ownerRunning
	o.listener = listener
	o.worker = worker
	o.workers = workers
	o.closed = make(chan struct{})
	workers.Start(func(ctx context.Context) { o.accept(ctx, listener, worker, sessionError) })
	workers.Start(func(ctx context.Context) { o.watch(ctx, worker, listener, workerExit) })
	return true
}

func (o *Owner) accept(ctx context.Context, listener net.Listener, worker Worker, sessionError func()) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		o.mu.Lock()
		running := o.phase == ownerRunning
		workers := o.workers
		o.mu.Unlock()
		if !running || workers == nil {
			_ = conn.Close()
			return
		}
		if !workers.Start(func(ctx context.Context) {
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

func (o *Owner) watch(ctx context.Context, worker Worker, listener net.Listener, workerExit func()) {
	select {
	case <-worker.Done():
	case <-ctx.Done():
		return
	}
	_ = listener.Close()
	o.mu.Lock()
	if o.phase == ownerRunning {
		o.phase = ownerExited
	}
	o.mu.Unlock()
	if workerExit != nil {
		workerExit()
	}
}

func (o *Owner) CloseSessions() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.phase == ownerRunning && o.worker != nil {
		o.worker.CloseSessions()
	}
}

func (o *Owner) ConfinementReport() (*workerconf.Report, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.phase != ownerRunning || o.worker == nil {
		return nil, false
	}
	select {
	case <-o.worker.Done():
		return nil, false
	default:
		return o.worker.ConfinementReport(), true
	}
}

func (o *Owner) Close() error {
	o.mu.Lock()
	switch o.phase {
	case ownerIdle, ownerClosed:
		o.mu.Unlock()
		return nil
	case ownerStopping:
		closed := o.closed
		o.mu.Unlock()
		if closed != nil {
			<-closed
		}
		return nil
	case ownerRunning, ownerExited:
		o.phase = ownerStopping
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
		workers.Close()
	}

	o.mu.Lock()
	o.listener = nil
	o.worker = nil
	o.workers = nil
	o.phase = ownerClosed
	if o.closed != nil {
		close(o.closed)
		o.closed = nil
	}
	o.mu.Unlock()
	return err
}
