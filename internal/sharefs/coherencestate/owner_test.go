package coherencestate

import (
	"sync"
	"testing"
)

func TestOwnerTransitions(t *testing.T) {
	var owner Owner
	if owner.Phase() != Initializing || owner.Healthy() {
		t.Fatalf("zero owner phase = %d healthy=%v", owner.Phase(), owner.Healthy())
	}
	if !owner.Activate() || !owner.Healthy() {
		t.Fatal("owner did not become healthy")
	}
	if owner.Activate() {
		t.Fatal("owner activated twice")
	}
	if !owner.Degrade() || owner.Phase() != Degraded {
		t.Fatalf("owner did not degrade: %d", owner.Phase())
	}
	if owner.Degrade() {
		t.Fatal("duplicate degradation claimed cache-flush ownership")
	}
	leader, done := owner.BeginClose()
	if !leader || owner.Phase() != Closing {
		t.Fatalf("close leader=%v phase=%d", leader, owner.Phase())
	}
	if duplicate, duplicateDone := owner.BeginClose(); duplicate || duplicateDone != done {
		t.Fatal("duplicate close did not join the release owner")
	}
	select {
	case <-done:
		t.Fatal("close completed before resource release")
	default:
	}
	if !owner.FinishClose() || owner.Phase() != Closed {
		t.Fatalf("owner did not close: %d", owner.Phase())
	}
	<-done
	if owner.FinishClose() || owner.Activate() || owner.Degrade() {
		t.Fatal("closed owner accepted another transition")
	}
}

func TestOwnerHasOneConcurrentCloseLeader(t *testing.T) {
	var owner Owner
	owner.Activate()
	const callers = 32
	var wait sync.WaitGroup
	wait.Add(callers)
	leaders := make(chan bool, callers)
	for range callers {
		go func() {
			defer wait.Done()
			leader, _ := owner.BeginClose()
			leaders <- leader
		}()
	}
	wait.Wait()
	close(leaders)
	count := 0
	for leader := range leaders {
		if leader {
			count++
		}
	}
	if count != 1 || owner.Phase() != Closing {
		t.Fatalf("close leaders=%d phase=%d", count, owner.Phase())
	}
	owner.FinishClose()
}
