package selectionstate

import "testing"

func TestOwnerBoundsTablePositions(t *testing.T) {
	var owner Owner
	if owner.SetTableCursor(Slot(255), 1, 2) {
		t.Fatal("invalid slot was admitted")
	}
	if !owner.SetTableCursor(Traffic, 9, 5) {
		t.Fatal("valid slot was rejected")
	}
	cursor, scroll, ok := owner.TablePosition(Traffic)
	if !ok || cursor != 4 || scroll != 0 {
		t.Fatalf("position = %d/%d, %v", cursor, scroll, ok)
	}
	if !owner.EnsureTableVisible(Traffic, 5, 2) {
		t.Fatal("visibility update was rejected")
	}
	cursor, scroll, _ = owner.TablePosition(Traffic)
	if cursor != 4 || scroll != 3 {
		t.Fatalf("visible position = %d/%d", cursor, scroll)
	}
	if !owner.MoveTable(Traffic, -2, 5) {
		t.Fatal("move was rejected")
	}
	owner.EnsureTableVisible(Traffic, 5, 2)
	cursor, scroll, _ = owner.TablePosition(Traffic)
	if cursor != 2 || scroll != 2 {
		t.Fatalf("moved position = %d/%d", cursor, scroll)
	}
	owner.EnsureTableVisible(Traffic, 0, 2)
	cursor, scroll, _ = owner.TablePosition(Traffic)
	if cursor != 0 || scroll != 0 {
		t.Fatalf("empty position = %d/%d", cursor, scroll)
	}
}

func TestOwnerBoundsCardViewports(t *testing.T) {
	var owner Owner
	owner.SetCardCursor(8, 9)
	owner.EnsureCardListVisible(9, 3)
	cursor, scroll := owner.CardPosition()
	if cursor != 8 || scroll != 6 {
		t.Fatalf("list position = %d/%d", cursor, scroll)
	}
	owner.SetCardCursor(5, 8)
	owner.EnsureCardGridVisible(8, 3, 1, 2)
	cursor, scroll = owner.CardPosition()
	if cursor != 5 || scroll != 1 {
		t.Fatalf("grid position = %d/%d", cursor, scroll)
	}
	owner.ResetCards()
	cursor, scroll = owner.CardPosition()
	if cursor != 0 || scroll != 0 {
		t.Fatalf("reset position = %d/%d", cursor, scroll)
	}
}
