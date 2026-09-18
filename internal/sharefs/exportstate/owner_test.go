package exportstate

import (
	"sync"
	"testing"
)

func TestOwnerTransitions(t *testing.T) {
	var owner Owner
	if owner.Phase() != Active {
		t.Fatalf("zero phase = %s, want active", owner.Phase())
	}
	if owner.Transition(Gone) {
		t.Fatal("active owner skipped directly to gone")
	}
	if !owner.Transition(Draining) || !owner.Transition(Revoked) || !owner.Transition(Gone) {
		t.Fatalf("valid lifecycle stopped at %s", owner.Phase())
	}
	if owner.Transition(Revoked) || owner.Phase() != Gone {
		t.Fatal("terminal owner regressed")
	}
}

func TestOwnerConcurrentRevokeDoesNotRegress(t *testing.T) {
	var owner Owner
	const callers = 32
	var wait sync.WaitGroup
	wait.Add(callers)
	for range callers {
		go func() {
			defer wait.Done()
			owner.Transition(Revoked)
		}()
	}
	wait.Wait()
	if owner.Phase() != Revoked {
		t.Fatalf("phase after concurrent revoke = %s", owner.Phase())
	}
	if !owner.Transition(Gone) || owner.Transition(Draining) {
		t.Fatalf("terminal transition regressed to %s", owner.Phase())
	}
}
