package pagestate

import "testing"

func TestOwnerTransitionsAndCyclesExplicitOrder(t *testing.T) {
	owner := New(2, 4, []Page{2, 0, 3, 1, 3, 9})
	if owner.Current() != 2 {
		t.Fatalf("initial page = %d", owner.Current())
	}
	if next := owner.Cycle(1); next != 0 {
		t.Fatalf("next page = %d, want 0", next)
	}
	if !owner.Transition(0) || owner.Current() != 0 {
		t.Fatal("valid transition was rejected")
	}
	if next := owner.Cycle(-1); next != 2 {
		t.Fatalf("previous page = %d, want 2", next)
	}
	if owner.Transition(4) {
		t.Fatal("out-of-range transition was admitted")
	}
	if owner.Current() != 0 {
		t.Fatal("rejected transition changed current page")
	}
}

func TestOwnerSuppliesNavigableFallbackOrder(t *testing.T) {
	owner := New(8, 3, nil)
	if owner.Current() != 0 || owner.Cycle(1) != 0 {
		t.Fatalf("fallback owner = current %d next %d", owner.Current(), owner.Cycle(1))
	}
}
