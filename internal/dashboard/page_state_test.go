package dashboard

import "testing"

func TestTUIPageStateTransitionsAndOrder(t *testing.T) {
	state := newTUIPageState()
	if state.page != tuiOverviewPage {
		t.Fatalf("initial page = %d", state.page)
	}
	for _, want := range tuiPageOrder[1:] {
		if next := state.cycle(1); next != want {
			t.Fatalf("next page = %d, want %d", next, want)
		}
		if !state.transition(want) {
			t.Fatalf("transition to %d was rejected", want)
		}
	}
	if next := state.cycle(1); next != tuiOverviewPage {
		t.Fatalf("wrap page = %d, want overview", next)
	}
	if state.transition(tuiPageCount) {
		t.Fatal("out-of-range page was admitted")
	}
	if state.page != tuiRemotesPage {
		t.Fatalf("rejected transition changed page to %d", state.page)
	}
	if next := state.cycle(-1); next != tuiImagesPage {
		t.Fatalf("reverse page = %d, want images", next)
	}
}
