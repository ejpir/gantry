// Package selectionstate owns bounded dashboard cursor and viewport state.
package selectionstate

// Slot identifies an independently scrolling table.
type Slot uint8

const (
	Traffic Slot = iota
	Rules
	Mounts
	Ports
	Secrets
	MCP
	Audit
	Remote
	Image
	Registry
	Packet
	slotCount
)

type position struct {
	cursor int
	scroll int
}

// Owner owns card and table cursor/viewport positions.
type Owner struct {
	cards  position
	tables [slotCount]position
}

// TablePosition returns one table's cursor and scroll position.
func (owner *Owner) TablePosition(slot Slot) (cursor, scroll int, ok bool) {
	position, ok := owner.table(slot)
	if !ok {
		return 0, 0, false
	}
	return position.cursor, position.scroll, true
}

// SetTableCursor clamps a table cursor to its current row count.
func (owner *Owner) SetTableCursor(slot Slot, index, count int) bool {
	position, ok := owner.table(slot)
	if !ok {
		return false
	}
	position.cursor = clampCursor(index, count)
	return true
}

// ResetTable returns a table cursor and viewport to their origins.
func (owner *Owner) ResetTable(slot Slot) bool {
	selected, ok := owner.table(slot)
	if !ok {
		return false
	}
	*selected = position{}
	return true
}

// MoveTable moves a table cursor within the current row count.
func (owner *Owner) MoveTable(slot Slot, delta, count int) bool {
	position, ok := owner.table(slot)
	if !ok || count <= 0 {
		return false
	}
	position.cursor = clamp(position.cursor+delta, 0, count-1)
	return true
}

// TableBoundary moves a cursor to the first or last row.
func (owner *Owner) TableBoundary(slot Slot, end bool, count int) bool {
	position, ok := owner.table(slot)
	if !ok || count <= 0 {
		return false
	}
	position.cursor = 0
	if end {
		position.cursor = count - 1
	}
	return true
}

// EnsureTableVisible clamps a table position and scrolls to expose its cursor.
func (owner *Owner) EnsureTableVisible(slot Slot, count, visible int) bool {
	selected, ok := owner.table(slot)
	if !ok {
		return false
	}
	if count <= 0 {
		*selected = position{}
		return true
	}
	selected.cursor = clamp(selected.cursor, 0, count-1)
	visible = maximum(1, visible)
	if selected.cursor < selected.scroll {
		selected.scroll = selected.cursor
	}
	if selected.cursor >= selected.scroll+visible {
		selected.scroll = selected.cursor - visible + 1
	}
	selected.scroll = clamp(selected.scroll, 0, maximum(0, count-visible))
	return true
}

// CardPosition returns the card cursor and viewport row.
func (owner *Owner) CardPosition() (cursor, scroll int) {
	if owner == nil {
		return 0, 0
	}
	return owner.cards.cursor, owner.cards.scroll
}

// SetCardCursor clamps the card cursor to the current entry count.
func (owner *Owner) SetCardCursor(index, count int) {
	if owner != nil {
		owner.cards.cursor = clampCursor(index, count)
	}
}

// ResetCards returns card navigation to its origin.
func (owner *Owner) ResetCards() {
	if owner != nil {
		owner.cards = position{}
	}
}

// EnsureCardListVisible scrolls a vertical card list to expose its cursor.
func (owner *Owner) EnsureCardListVisible(count, visible int) {
	if owner == nil {
		return
	}
	owner.cards.cursor = clampCursor(owner.cards.cursor, count)
	visible = maximum(1, visible)
	if owner.cards.cursor < owner.cards.scroll {
		owner.cards.scroll = owner.cards.cursor
	}
	if owner.cards.cursor >= owner.cards.scroll+visible {
		owner.cards.scroll = owner.cards.cursor - visible + 1
	}
	owner.cards.scroll = clamp(owner.cards.scroll, 0, maximum(0, count-visible))
}

// EnsureCardGridVisible scrolls a card grid to expose its cursor row.
func (owner *Owner) EnsureCardGridVisible(count, columns, visibleRows, maxScroll int) {
	if owner == nil {
		return
	}
	columns, visibleRows = maximum(1, columns), maximum(1, visibleRows)
	owner.cards.cursor = clampCursor(owner.cards.cursor, count)
	row := owner.cards.cursor / columns
	if row < owner.cards.scroll {
		owner.cards.scroll = row
	}
	if row >= owner.cards.scroll+visibleRows {
		owner.cards.scroll = row - visibleRows + 1
	}
	owner.cards.scroll = clamp(owner.cards.scroll, 0, maximum(0, maxScroll))
}

func (owner *Owner) table(slot Slot) (*position, bool) {
	if owner == nil || slot >= slotCount {
		return nil, false
	}
	return &owner.tables[slot], true
}

func clampCursor(cursor, count int) int {
	if count <= 0 {
		return 0
	}
	return clamp(cursor, 0, count-1)
}

func clamp(value, low, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func maximum(a, b int) int {
	if a > b {
		return a
	}
	return b
}
