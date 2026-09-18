package dashboard

import "github.com/ejpir/gantry/internal/dashboard/pagestate"

// tuiPageState adapts the framework-independent page owner to dashboard page
// identifiers. page is a read-only projection used by rendering code.
type tuiPageState struct {
	owner pagestate.Owner
	page  tuiPage
}

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

func newTUIPageState() tuiPageState {
	order := make([]pagestate.Page, len(tuiPageOrder))
	for index, page := range tuiPageOrder {
		order[index] = pagestate.Page(page)
	}
	owner := pagestate.New(pagestate.Page(tuiOverviewPage), pagestate.Page(tuiPageCount), order)
	return tuiPageState{owner: owner, page: tuiOverviewPage}
}

func (state *tuiPageState) transition(next tuiPage) bool {
	if state == nil || !state.owner.Transition(pagestate.Page(next)) {
		return false
	}
	state.page = tuiPage(state.owner.Current())
	return true
}

func (state *tuiPageState) cycle(delta int) tuiPage {
	if state == nil {
		return tuiOverviewPage
	}
	return tuiPage(state.owner.Cycle(delta))
}
