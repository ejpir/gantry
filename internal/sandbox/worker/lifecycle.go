// Package worker is the substrate the split child processes are built on: a
// process-neutral lifecycle state machine, the confinement and handle-passing
// primitives each platform needs to spawn one, and the environment allowlist
// they inherit.
//
// It deliberately knows nothing about what a worker does — the VMM worker and
// the netstack worker own their own RPC, transports and process handles — so
// both can sit on it without either depending on the other.
package worker

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

type Containment interface {
	Close() error
}

type Phase uint8

const (
	PhaseRunning Phase = iota
	PhaseStopping
	PhaseExited
)

// Lifecycle is the shared, process-neutral state machine for split
// workers. It deliberately knows nothing about RPC clients, transports, or
// process handles: those remain owned by each worker implementation.
type Lifecycle struct {
	stopping chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	exitOnce sync.Once

	mu      sync.RWMutex
	phase   Phase
	exitErr error
}

func WaitProcess(process *os.Process, role string) error {
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

func NewLifecycle() *Lifecycle {
	return &Lifecycle{
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
		phase:    PhaseRunning,
	}
}

// BeginStop marks an intentional shutdown. Unexpected process death calls
// Exit directly, preserving the distinction for relay and RPC goroutines.
func (l *Lifecycle) BeginStop() {
	l.stopOnce.Do(func() {
		l.mu.Lock()
		if l.phase == PhaseRunning {
			l.phase = PhaseStopping
		}
		l.mu.Unlock()
		close(l.stopping)
	})
}

// Exit publishes the process result before waking every observer. It is
// idempotent because process failure and cleanup paths can race.
func (l *Lifecycle) Exit(err error) {
	l.exitOnce.Do(func() {
		l.mu.Lock()
		l.phase = PhaseExited
		l.exitErr = err
		l.mu.Unlock()
		close(l.done)
	})
}

func (l *Lifecycle) Stopping() <-chan struct{} { return l.stopping }
func (l *Lifecycle) Done() <-chan struct{}     { return l.done }

// Err is stable once Done closes.
func (l *Lifecycle) Err() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.exitErr
}

func (l *Lifecycle) Phase() Phase {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.phase
}

// WaitExit allows one grace period, invokes kill at most once, then allows a
// second grace period for the process watcher to reap the child. It never
// waits forever on a failed kill or a broken watcher.
func (l *Lifecycle) WaitExit(grace time.Duration, kill func() error) error {
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
