package dashboard

import "github.com/ejpir/gantry/internal/dashboard/selectionstate"

type tuiSelectionSlot = selectionstate.Slot

const (
	tuiTrafficSelection  = selectionstate.Traffic
	tuiRulesSelection    = selectionstate.Rules
	tuiMountsSelection   = selectionstate.Mounts
	tuiPortsSelection    = selectionstate.Ports
	tuiSecretsSelection  = selectionstate.Secrets
	tuiMCPSelection      = selectionstate.MCP
	tuiAuditSelection    = selectionstate.Audit
	tuiRemoteSelection   = selectionstate.Remote
	tuiImageSelection    = selectionstate.Image
	tuiRegistrySelection = selectionstate.Registry
	tuiPacketSelection   = selectionstate.Packet
)

// tuiSelectionState adapts the framework-independent selection owner. Its
// cursor fields are read-only projections retained for rendering code.
type tuiSelectionState struct {
	owner selectionstate.Owner

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

func (state *tuiSelectionState) tablePosition(slot tuiSelectionSlot) (cursor, scroll int, ok bool) {
	return state.owner.TablePosition(slot)
}

func (state *tuiSelectionState) setTableCursor(slot tuiSelectionSlot, index, count int) bool {
	if !state.owner.SetTableCursor(slot, index, count) {
		return false
	}
	state.syncTable(slot)
	return true
}

func (state *tuiSelectionState) resetTable(slot tuiSelectionSlot) bool {
	if !state.owner.ResetTable(slot) {
		return false
	}
	state.syncTable(slot)
	return true
}

func (state *tuiSelectionState) moveTable(slot tuiSelectionSlot, delta, count int) bool {
	if !state.owner.MoveTable(slot, delta, count) {
		return false
	}
	state.syncTable(slot)
	return true
}

func (state *tuiSelectionState) tableBoundary(slot tuiSelectionSlot, end bool, count int) bool {
	if !state.owner.TableBoundary(slot, end, count) {
		return false
	}
	state.syncTable(slot)
	return true
}

func (state *tuiSelectionState) ensureTableVisible(slot tuiSelectionSlot, count, visible int) bool {
	if !state.owner.EnsureTableVisible(slot, count, visible) {
		return false
	}
	state.syncTable(slot)
	return true
}

func (state *tuiSelectionState) setCardCursor(index, count int) {
	state.owner.SetCardCursor(index, count)
	state.syncCards()
}

func (state *tuiSelectionState) resetCards() {
	state.owner.ResetCards()
	state.syncCards()
}

func (state *tuiSelectionState) ensureCardListVisible(count, visible int) {
	state.owner.EnsureCardListVisible(count, visible)
	state.syncCards()
}

func (state *tuiSelectionState) ensureCardGridVisible(count, columns, visibleRows, maxScroll int) {
	state.owner.EnsureCardGridVisible(count, columns, visibleRows, maxScroll)
	state.syncCards()
}

func (state *tuiSelectionState) syncCards() {
	state.cursor, state.scrollRow = state.owner.CardPosition()
}

func (state *tuiSelectionState) syncTable(slot tuiSelectionSlot) {
	cursor, scroll, ok := state.owner.TablePosition(slot)
	if !ok {
		return
	}
	switch slot {
	case tuiTrafficSelection:
		state.trafficCursor, state.trafficScroll = cursor, scroll
	case tuiRulesSelection:
		state.rulesCursor, state.rulesScroll = cursor, scroll
	case tuiMountsSelection:
		state.mountCursor, state.mountScroll = cursor, scroll
	case tuiPortsSelection:
		state.portCursor, state.portScroll = cursor, scroll
	case tuiSecretsSelection:
		state.secretCursor, state.secretScroll = cursor, scroll
	case tuiMCPSelection:
		state.mcpCursor, state.mcpScroll = cursor, scroll
	case tuiAuditSelection:
		state.auditCursor, state.auditScroll = cursor, scroll
	case tuiRemoteSelection:
		state.remoteCursor, state.remoteScroll = cursor, scroll
	case tuiImageSelection:
		state.imageCursor, state.imageScroll = cursor, scroll
	case tuiRegistrySelection:
		state.registryCursor, state.registryScroll = cursor, scroll
	case tuiPacketSelection:
		state.packetCursor, state.packetScroll = cursor, scroll
	}
}
