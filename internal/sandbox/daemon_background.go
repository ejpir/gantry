package sandbox

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

// backgroundGroup is a one-shot owner for cancellable goroutines. Admission
// and shutdown share one lock, so Wait can never race a zero-to-one WaitGroup
// transition. close cancels every borrower and does not return until all of
// them have released the context.
type backgroundGroup struct {
	mu     sync.Mutex
	phase  backgroundPhase
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed chan struct{}
}

// acquire borrows the group context and returns its release function. The
// caller must release exactly once when admitted.
func (g *backgroundGroup) acquire() (context.Context, func(), bool) {
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

func (g *backgroundGroup) start(run func(context.Context)) bool {
	if run == nil {
		return false
	}
	ctx, done, ok := g.acquire()
	if !ok {
		return false
	}
	go func() {
		defer done()
		run(ctx)
	}()
	return true
}

func (g *backgroundGroup) close() {
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
