package sandbox

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

type workerPhase uint8

const (
	workerRunning workerPhase = iota
	workerStopping
	workerExited
)

// workerLifecycle is the shared, process-neutral state machine for split
// workers. It deliberately knows nothing about RPC clients, transports, or
// process handles: those remain owned by each worker implementation.
type workerLifecycle struct {
	stopping chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	exitOnce sync.Once

	mu      sync.RWMutex
	phase   workerPhase
	exitErr error
}

func waitProcess(process *os.Process, role string) error {
	state, err := process.Wait()
	if err != nil {
		return fmt.Errorf("%s wait: %w", role, err)
	}
	if state == nil {
		return fmt.Errorf("%s wait returned no process state", role)
	}
	if !state.Success() {
		return fmt.Errorf("%s %s", role, state)
	}
	return nil
}

func newWorkerLifecycle() *workerLifecycle {
	return &workerLifecycle{
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
		phase:    workerRunning,
	}
}

// BeginStop marks an intentional shutdown. Unexpected process death calls
// Exit directly, preserving the distinction for relay and RPC goroutines.
func (l *workerLifecycle) BeginStop() {
	l.stopOnce.Do(func() {
		l.mu.Lock()
		if l.phase == workerRunning {
			l.phase = workerStopping
		}
		l.mu.Unlock()
		close(l.stopping)
	})
}

// Exit publishes the process result before waking every observer. It is
// idempotent because process failure and cleanup paths can race.
func (l *workerLifecycle) Exit(err error) {
	l.exitOnce.Do(func() {
		l.mu.Lock()
		l.phase = workerExited
		l.exitErr = err
		l.mu.Unlock()
		close(l.done)
	})
}

func (l *workerLifecycle) Stopping() <-chan struct{} { return l.stopping }
func (l *workerLifecycle) Done() <-chan struct{}     { return l.done }

// Err is stable once Done closes.
func (l *workerLifecycle) Err() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.exitErr
}

func (l *workerLifecycle) Phase() workerPhase {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.phase
}

// WaitExit allows one grace period, invokes kill at most once, then allows a
// second grace period for the process watcher to reap the child. It never
// waits forever on a failed kill or a broken watcher.
func (l *workerLifecycle) WaitExit(grace time.Duration, kill func() error) error {
	if grace <= 0 {
		return fmt.Errorf("worker exit grace period must be positive")
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-l.done:
		return l.Err()
	case <-timer.C:
	}

	if kill == nil {
		return fmt.Errorf("worker did not exit within %s", grace)
	}
	killErr := kill()
	timer.Reset(grace)
	select {
	case <-l.done:
		return l.Err()
	case <-timer.C:
		return errors.Join(fmt.Errorf("worker was not reaped within %s after kill", grace), killErr)
	}
}
