package supervisor

import (
	"context"
	"sync"
)

type backgroundPhase uint8

const (
	backgroundOpen backgroundPhase = iota
	backgroundClosing
	backgroundClosed
)

// BackgroundGroup is a one-shot owner for cancellable goroutines. Admission
// and shutdown share one lock, so Wait can never race a zero-to-one WaitGroup
// transition. Close cancels every borrower and joins it before returning.
type BackgroundGroup struct {
	mu     sync.Mutex
	phase  backgroundPhase
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed chan struct{}
}

// Acquire borrows the group context and returns its release function. The
// caller must release exactly once when admitted.
func (g *BackgroundGroup) Acquire() (context.Context, func(), bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.phase != backgroundOpen {
		return nil, nil, false
	}
	if g.ctx == nil {
		g.ctx, g.cancel = context.WithCancel(context.Background())
		g.closed = make(chan struct{})
	}
	g.wg.Add(1)
	return g.ctx, g.wg.Done, true
}

// Start admits and launches one cancellable task.
func (g *BackgroundGroup) Start(run func(context.Context)) bool {
	if run == nil {
		return false
	}
	ctx, done, ok := g.Acquire()
	if !ok {
		return false
	}
	go func() {
		defer done()
		run(ctx)
	}()
	return true
}

// Close prevents new tasks, cancels current tasks, and joins them. It is safe
// for repeated and concurrent callers.
func (g *BackgroundGroup) Close() {
	g.mu.Lock()
	switch g.phase {
	case backgroundClosed:
		g.mu.Unlock()
		return
	case backgroundClosing:
		closed := g.closed
		g.mu.Unlock()
		if closed != nil {
			<-closed
		}
		return
	case backgroundOpen:
		g.phase = backgroundClosing
		if g.closed == nil {
			g.closed = make(chan struct{})
		}
	}
	cancel, closed := g.cancel, g.closed
	g.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	g.wg.Wait()

	g.mu.Lock()
	if g.phase != backgroundClosed {
		g.phase = backgroundClosed
		close(closed)
	}
	g.mu.Unlock()
}
