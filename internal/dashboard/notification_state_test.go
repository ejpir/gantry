package dashboard

import "testing"

func TestTUINotificationStateRejectsStaleExpiry(t *testing.T) {
	var state tuiNotificationState
	if state.phase() != tuiNotificationIdle || state.dismiss() {
		t.Fatal("zero notification state is not idle")
	}
	first := state.publish(tuiToastInfo, "first", "one")
	second := state.publish(tuiToastSuccess, "second", "two")
	if first == second || state.phase() != tuiNotificationVisible {
		t.Fatalf("replacement state = %+v", state)
	}
	if state.expire(first) {
		t.Fatal("stale expiry cleared replacement toast")
	}
	if state.toast == nil || state.toast.title != "second" {
		t.Fatalf("replacement toast changed: %+v", state.toast)
	}
	if !state.expire(second) || state.phase() != tuiNotificationIdle {
		t.Fatalf("current toast did not expire: %+v", state)
	}
	if state.expire(second) {
		t.Fatal("duplicate expiry was accepted")
	}
}
