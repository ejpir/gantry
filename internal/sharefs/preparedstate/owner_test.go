package preparedstate

import (
	"sync"
	"testing"
	"time"
)

func TestFailedAttemptReturnsPreparedOwnership(t *testing.T) {
	var owner Owner
	first, ok := owner.Acquire()
	if !ok || owner.Phase() != InUse {
		t.Fatalf("first acquire ok=%v phase=%d", ok, owner.Phase())
	}
	if !owner.Complete(first, false) || owner.Phase() != Prepared {
		t.Fatalf("failed attempt did not restore prepared phase: %d", owner.Phase())
	}
	second, ok := owner.Acquire()
	if !ok || second == first {
		t.Fatal("replacement attempt did not receive a fresh lease")
	}
	if owner.Complete(first, true) {
		t.Fatal("stale lease consumed the replacement attempt")
	}
	if !owner.Complete(second, true) || owner.Phase() != Consumed {
		t.Fatalf("successful attempt did not consume ownership: %d", owner.Phase())
	}
	if _, ok := owner.Acquire(); ok {
		t.Fatal("consumed owner admitted another attempt")
	}
	leader, done := owner.BeginClose()
	if leader {
		t.Fatal("consumed owner claimed resource release")
	}
	<-done
}

func TestCloseWaitsForAttemptAndJoinsRelease(t *testing.T) {
	var owner Owner
	lease, ok := owner.Acquire()
	if !ok {
		t.Fatal("acquire failed")
	}
	leaderResult := make(chan bool, 1)
	leaderDone := make(chan (<-chan struct{}), 1)
	go func() {
		leader, done := owner.BeginClose()
		leaderResult <- leader
		leaderDone <- done
	}()
	select {
	case <-leaderResult:
		t.Fatal("close passed an active publication attempt")
	case <-time.After(20 * time.Millisecond):
	}
	if !owner.Complete(lease, false) {
		t.Fatal("attempt completion was rejected")
	}
	if leader := <-leaderResult; !leader {
		t.Fatal("close did not claim restored ownership")
	}
	done := <-leaderDone
	duplicateLeader, duplicateDone := owner.BeginClose()
	if duplicateLeader || duplicateDone != done {
		t.Fatal("duplicate close did not join release")
	}
	select {
	case <-duplicateDone:
		t.Fatal("close completed before release")
	default:
	}
	if !owner.FinishClose() || owner.Phase() != Closed {
		t.Fatalf("terminal phase = %d", owner.Phase())
	}
	<-duplicateDone
}

func TestOnlyOneConcurrentAcquireConsumesOwner(t *testing.T) {
	var owner Owner
	const callers = 16
	var wait sync.WaitGroup
	wait.Add(callers)
	successes := make(chan bool, callers)
	for range callers {
		go func() {
			defer wait.Done()
			lease, ok := owner.Acquire()
			if ok {
				owner.Complete(lease, true)
			}
			successes <- ok
		}()
	}
	wait.Wait()
	close(successes)
	count := 0
	for success := range successes {
		if success {
			count++
		}
	}
	if count != 1 || owner.Phase() != Consumed {
		t.Fatalf("successful consumers=%d phase=%d", count, owner.Phase())
	}
}
