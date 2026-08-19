package main

import (
	"sync"
	"testing"
	"time"
)

func TestFailedCommandCancelsUpdateCheckWithoutGraceWait(t *testing.T) {
	checkDone := make(chan struct{})
	var cancelOnce sync.Once
	check := &updateCheck{
		done: checkDone,
		cancel: func() {
			cancelOnce.Do(func() { close(checkDone) })
		},
	}
	returned := make(chan struct{})
	go func() {
		maybeNotifyUpdate([]string{"start", "dev"}, 1, check)
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(updateCheckGrace / 2):
		// Release an implementation still waiting for the full grace period so
		// the failed assertion does not strand its goroutine.
		cancelOnce.Do(func() { close(checkDone) })
		<-returned
		t.Fatal("failed command waited for update-check grace period")
	}
	select {
	case <-checkDone:
	default:
		t.Fatal("failed command did not cancel its update check")
	}
}
