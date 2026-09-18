package dashboard

import "testing"

func TestTUISelectionStateBoundsTablePositions(t *testing.T) {
	var state tuiSelectionState
	if state.setTableCursor(tuiSelectionSlot(255), 1, 2) {
		t.Fatal("invalid selection slot was accepted")
	}
	if !state.setTableCursor(tuiTrafficSelection, 9, 5) || state.trafficCursor != 4 {
		t.Fatalf("bounded cursor = %d, want 4", state.trafficCursor)
	}
	if !state.ensureTableVisible(tuiTrafficSelection, 5, 2) {
		t.Fatal("traffic selection was not recognized")
	}
	if state.trafficScroll != 3 {
		t.Fatalf("visible scroll = %d, want 3", state.trafficScroll)
	}
	if !state.moveTable(tuiTrafficSelection, -2, 5) || state.trafficCursor != 2 {
		t.Fatalf("moved cursor = %d, want 2", state.trafficCursor)
	}
	state.ensureTableVisible(tuiTrafficSelection, 5, 2)
	if state.trafficScroll != 2 {
		t.Fatalf("moved scroll = %d, want 2", state.trafficScroll)
	}
	if !state.tableBoundary(tuiTrafficSelection, false, 5) || state.trafficCursor != 0 {
		t.Fatalf("start boundary = %d", state.trafficCursor)
	}
	if !state.tableBoundary(tuiTrafficSelection, true, 5) || state.trafficCursor != 4 {
		t.Fatalf("end boundary = %d", state.trafficCursor)
	}
	state.ensureTableVisible(tuiTrafficSelection, 0, 2)
	if state.trafficCursor != 0 || state.trafficScroll != 0 {
		t.Fatalf("empty position = %d/%d", state.trafficCursor, state.trafficScroll)
	}
}

func TestTUISelectionStateBoundsCardViewports(t *testing.T) {
	var state tuiSelectionState
	state.setCardCursor(8, 9)
	state.ensureCardListVisible(9, 3)
	if state.cursor != 8 || state.scrollRow != 6 {
		t.Fatalf("list position = %d/%d, want 8/6", state.cursor, state.scrollRow)
	}
	state.setCardCursor(5, 8)
	state.ensureCardGridVisible(8, 3, 1, 2)
	if state.cursor != 5 || state.scrollRow != 1 {
		t.Fatalf("grid position = %d/%d, want 5/1", state.cursor, state.scrollRow)
	}
	state.setCardCursor(-10, 0)
	state.ensureCardListVisible(0, 0)
	if state.cursor != 0 || state.scrollRow != 0 {
		t.Fatalf("empty cards = %d/%d", state.cursor, state.scrollRow)
	}
}
