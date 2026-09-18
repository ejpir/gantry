package notificationstate

import "testing"

func TestOwnerRejectsStaleAndDuplicateExpiry(t *testing.T) {
	var owner Owner
	if owner.Phase() != Idle || owner.Dismiss() {
		t.Fatal("zero owner is not idle")
	}
	first := owner.Publish(1, "first", "one")
	second := owner.Publish(2, "second", "two")
	if first == second || owner.Phase() != Visible {
		t.Fatal("replacement did not advance generation")
	}
	if owner.Expire(first) {
		t.Fatal("stale expiry cleared replacement")
	}
	current, ok := owner.Current()
	if !ok || current.Title != "second" || current.Generation != second {
		t.Fatalf("current notification = %+v, %v", current, ok)
	}
	if !owner.Expire(second) || owner.Phase() != Idle {
		t.Fatal("current notification did not expire")
	}
	if owner.Expire(second) {
		t.Fatal("duplicate expiry was accepted")
	}
}

func TestOwnerDismissesCurrentGeneration(t *testing.T) {
	var owner Owner
	owner.Publish(1, "title", "body")
	if !owner.Dismiss() || owner.Dismiss() {
		t.Fatal("dismissal was not single-use")
	}
	if _, ok := owner.Current(); ok {
		t.Fatal("dismissed notification remains visible")
	}
}
