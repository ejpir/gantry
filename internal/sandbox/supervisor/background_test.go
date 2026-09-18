package supervisor

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestBackgroundGroupCancelsJoinsAndClosesAdmission(t *testing.T) {
	var group BackgroundGroup
	started := make(chan struct{})
	exited := make(chan struct{})
	if !group.Start(func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		close(exited)
	}) {
		t.Fatal("initial background task was rejected")
	}
	<-started
	group.Close()
	select {
	case <-exited:
	default:
		t.Fatal("Close returned before the task exited")
	}
	if group.Start(func(context.Context) {}) {
		t.Fatal("task admitted after Close")
	}
	var callers sync.WaitGroup
	for range 8 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			group.Close()
		}()
	}
	done := make(chan struct{})
	go func() { callers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent Close did not return")
	}
}
