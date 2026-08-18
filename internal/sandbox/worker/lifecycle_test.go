package worker

import (
	"errors"
	"testing"
	"time"
)

func TestWorkerLifecycleTransitions(t *testing.T) {
	lifecycle := NewLifecycle()
	if got := lifecycle.Phase(); got != PhaseRunning {
		t.Fatalf("initial phase = %d, want running", got)
	}

	lifecycle.BeginStop()
	lifecycle.BeginStop()
	if got := lifecycle.Phase(); got != PhaseStopping {
		t.Fatalf("stopping phase = %d, want stopping", got)
	}
	select {
	case <-lifecycle.Stopping():
	default:
		t.Fatal("stopping notification is not closed")
	}

	want := errors.New("worker failed")
	lifecycle.Exit(want)
	lifecycle.Exit(errors.New("later result"))
	if got := lifecycle.Phase(); got != PhaseExited {
		t.Fatalf("exit phase = %d, want exited", got)
	}
	if !errors.Is(lifecycle.Err(), want) {
		t.Fatalf("exit error = %v, want %v", lifecycle.Err(), want)
	}
	select {
	case <-lifecycle.Done():
	default:
		t.Fatal("exit notification is not closed")
	}
}

func TestWorkerLifecycleUnexpectedExitIsNotIntentionalStop(t *testing.T) {
	lifecycle := NewLifecycle()
	lifecycle.Exit(nil)
	select {
	case <-lifecycle.Stopping():
		t.Fatal("unexpected exit closed the intentional-stop notification")
	default:
	}
}

func TestWorkerLifecycleWaitExitBoundsKillAndReap(t *testing.T) {
	lifecycle := NewLifecycle()
	killed := make(chan struct{})
	err := lifecycle.WaitExit(time.Millisecond, func() error {
		close(killed)
		return errors.New("kill failed")
	})
	select {
	case <-killed:
	default:
		t.Fatal("kill was not attempted")
	}
	if err == nil {
		t.Fatal("missing bounded reap error")
	}
}
