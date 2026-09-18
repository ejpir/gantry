package dashboard

type tuiSelectionSlot uint8

const (
	tuiTrafficSelection tuiSelectionSlot = iota
	tuiRulesSelection
	tuiMountsSelection
	tuiPortsSelection
	tuiSecretsSelection
	tuiMCPSelection
	tuiAuditSelection
	tuiRemoteSelection
	tuiImageSelection
	tuiRegistrySelection
	tuiPacketSelection
)

// tuiSelectionState owns all page cursor and viewport positions. Rendering may
// inspect the promoted fields, but input and refresh paths mutate positions only
// through the bounded methods below.
type tuiSelectionState struct {
	cursor    int
	scrollRow int

	trafficCursor  int
	trafficScroll  int
	rulesCursor    int
	rulesScroll    int
	mountCursor    int
	mountScroll    int
	portCursor     int
	portScroll     int
	secretCursor   int
	secretScroll   int
	mcpCursor      int
	mcpScroll      int
	auditCursor    int
	auditScroll    int
	remoteCursor   int
	remoteScroll   int
	imageCursor    int
	imageScroll    int
	registryCursor int
	registryScroll int
	packetCursor   int
	packetScroll   int
}

func (state *tuiSelectionState) tablePointers(slot tuiSelectionSlot) (cursor, scroll *int) {
	switch slot {
	case tuiTrafficSelection:
		return &state.trafficCursor, &state.trafficScroll
	case tuiRulesSelection:
		return &state.rulesCursor, &state.rulesScroll
	case tuiMountsSelection:
		return &state.mountCursor, &state.mountScroll
	case tuiPortsSelection:
		return &state.portCursor, &state.portScroll
	case tuiSecretsSelection:
		return &state.secretCursor, &state.secretScroll
	case tuiMCPSelection:
		return &state.mcpCursor, &state.mcpScroll
	case tuiAuditSelection:
		return &state.auditCursor, &state.auditScroll
	case tuiRemoteSelection:
		return &state.remoteCursor, &state.remoteScroll
	case tuiImageSelection:
		return &state.imageCursor, &state.imageScroll
	case tuiRegistrySelection:
		return &state.registryCursor, &state.registryScroll
	case tuiPacketSelection:
		return &state.packetCursor, &state.packetScroll
	default:
		return nil, nil
	}
}

func (state *tuiSelectionState) tablePosition(slot tuiSelectionSlot) (cursor, scroll int, ok bool) {
	cursorPtr, scrollPtr := state.tablePointers(slot)
	if cursorPtr == nil {
		return 0, 0, false
	}
	return *cursorPtr, *scrollPtr, true
}

func (state *tuiSelectionState) setTableCursor(slot tuiSelectionSlot, index, count int) bool {
	cursor, _ := state.tablePointers(slot)
	if cursor == nil {
		return false
	}
	*cursor = clampTableCursor(index, count)
	return true
}

func (state *tuiSelectionState) resetTable(slot tuiSelectionSlot) bool {
	cursor, scroll := state.tablePointers(slot)
	if cursor == nil {
		return false
	}
	*cursor, *scroll = 0, 0
	return true
}

func (state *tuiSelectionState) moveTable(slot tuiSelectionSlot, delta, count int) bool {
	cursor, _ := state.tablePointers(slot)
	if cursor == nil || count == 0 {
		return false
	}
	*cursor = clampInt(*cursor+delta, 0, count-1)
	return true
}

func (state *tuiSelectionState) tableBoundary(slot tuiSelectionSlot, end bool, count int) bool {
	cursor, _ := state.tablePointers(slot)
	if cursor == nil || count == 0 {
		return false
	}
	*cursor = 0
	if end {
		*cursor = count - 1
	}
	return true
}

func (state *tuiSelectionState) ensureTableVisible(slot tuiSelectionSlot, count, visible int) bool {
	cursor, scroll := state.tablePointers(slot)
	if cursor == nil {
		return false
	}
	if count == 0 {
		*cursor, *scroll = 0, 0
		return true
	}
	*cursor = clampInt(*cursor, 0, count-1)
	visible = maxInt(1, visible)
	if *cursor < *scroll {
		*scroll = *cursor
	}
	if *cursor >= *scroll+visible {
		*scroll = *cursor - visible + 1
	}
	*scroll = clampInt(*scroll, 0, maxInt(0, count-visible))
	return true
}

func (state *tuiSelectionState) setCardCursor(index, count int) {
	state.cursor = clampInt(index, 0, maxInt(0, count-1))
}

func (state *tuiSelectionState) resetCards() { state.cursor, state.scrollRow = 0, 0 }

func (state *tuiSelectionState) ensureCardListVisible(count, visible int) {
	state.cursor = clampInt(state.cursor, 0, maxInt(0, count-1))
	visible = maxInt(1, visible)
	if state.cursor < state.scrollRow {
		state.scrollRow = state.cursor
	}
	if state.cursor >= state.scrollRow+visible {
		state.scrollRow = state.cursor - visible + 1
	}
	state.scrollRow = clampInt(state.scrollRow, 0, maxInt(0, count-visible))
}

func (state *tuiSelectionState) ensureCardGridVisible(count, columns, visibleRows, maxScroll int) {
	columns, visibleRows = maxInt(1, columns), maxInt(1, visibleRows)
	state.cursor = clampInt(state.cursor, 0, maxInt(0, count-1))
	row := state.cursor / columns
	if row < state.scrollRow {
		state.scrollRow = row
	}
	if row >= state.scrollRow+visibleRows {
		state.scrollRow = row - visibleRows + 1
	}
	state.scrollRow = clampInt(state.scrollRow, 0, maxInt(0, maxScroll))
}
