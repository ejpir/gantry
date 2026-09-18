package lifecycle

import (
	"sync"
	"testing"
)

func TestOwnerSerializesCloseAndJoinsFollowers(t *testing.T) {
	var owner Owner
	if owner.Phase() != Active {
		t.Fatalf("zero phase = %d, want active", owner.Phase())
	}
	leader, done := owner.BeginClose()
	if !leader || owner.Phase() != Stopping {
		t.Fatalf("begin close = leader %v phase %d", leader, owner.Phase())
	}
	follower, sameDone := owner.BeginClose()
	if follower || done != sameDone {
		t.Fatal("duplicate close did not join the active shutdown")
	}
	select {
	case <-done:
		t.Fatal("shutdown completed before resources were released")
	default:
	}
	if !owner.FinishClose() || owner.Phase() != Closed {
		t.Fatalf("finish close left phase %d", owner.Phase())
	}
	<-done
	if owner.FinishClose() {
		t.Fatal("duplicate terminal transition was accepted")
	}
	leader, closedDone := owner.BeginClose()
	if leader || closedDone != done {
		t.Fatal("close after terminal state did not join the original shutdown")
	}
}

func TestOwnerAdmitsOneConcurrentCloseLeader(t *testing.T) {
	var owner Owner
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
	if count != 1 {
		t.Fatalf("close leaders = %d, want 1", count)
	}
	owner.FinishClose()
}
