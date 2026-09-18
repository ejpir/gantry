package sandbox

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestBackgroundGroupCancelsJoinsAndClosesAdmission(t *testing.T) {
	var group backgroundGroup
	started := make(chan struct{})
	exited := make(chan struct{})
	if !group.start(func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		close(exited)
	}) {
		t.Fatal("initial background task was rejected")
	}
	<-started
	group.close()
	select {
	case <-exited:
	default:
		t.Fatal("close returned before the task exited")
	}
	if group.start(func(context.Context) {}) {
		t.Fatal("task admitted after close")
	}
	// Repeated and concurrent closes must observe the same joined terminal state.
	var callers sync.WaitGroup
	for range 8 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			group.close()
		}()
	}
	done := make(chan struct{})
	go func() { callers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent close did not return")
	}
}
