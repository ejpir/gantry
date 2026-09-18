package dashboard

// tuiPageState owns dashboard page transitions. The visible page order is
// explicit rather than relying on enum arithmetic because packet and audit
// views have independent polling/detail behavior.
type tuiPageState struct{ page tuiPage }

var tuiPageOrder = [...]tuiPage{
	tuiOverviewPage,
	tuiSandboxesPage,
	tuiTrafficPage,
	tuiRulesPage,
	tuiPortsPage,
	tuiPacketsPage,
	tuiMountsPage,
	tuiSecretsPage,
	tuiMCPPage,
	tuiAuditPage,
	tuiImagesPage,
	tuiRemotesPage,
}

func newTUIPageState() tuiPageState { return tuiPageState{page: tuiOverviewPage} }

func (state *tuiPageState) transition(next tuiPage) bool {
	if next >= tuiPageCount {
		return false
	}
	state.page = next
	return true
}

func (state *tuiPageState) cycle(delta int) tuiPage {
	current := 0
	for index, page := range tuiPageOrder {
		if page == state.page {
			current = index
			break
		}
	}
	next := (current + delta%len(tuiPageOrder) + len(tuiPageOrder)) % len(tuiPageOrder)
	return tuiPageOrder[next]
}
