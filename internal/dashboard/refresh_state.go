package dashboard

type tuiRefreshPhase uint8

const (
	tuiRefreshIdle tuiRefreshPhase = iota
	tuiRefreshRunning
)

// tuiRefreshOwner identifies the snapshot request that may publish dashboard
// rows. It prevents a slow pre-operation refresh from replacing a newer
// post-operation snapshot.
type tuiRefreshOwner struct{ generation uint64 }

type tuiRefreshState struct {
	refreshing     bool
	refreshVisible bool
	nextGeneration uint64
	owner          tuiRefreshOwner
}

func newTUIRefreshState() tuiRefreshState {
	var state tuiRefreshState
	state.restart(false)
	return state
}

func (state *tuiRefreshState) phase() tuiRefreshPhase {
	if state.refreshing {
		return tuiRefreshRunning
	}
	return tuiRefreshIdle
}

func (state *tuiRefreshState) begin(visible bool) (tuiRefreshOwner, bool) {
	if state.phase() != tuiRefreshIdle {
		return tuiRefreshOwner{}, false
	}
	return state.restart(visible), true
}

func (state *tuiRefreshState) restart(visible bool) tuiRefreshOwner {
	state.nextGeneration++
	state.owner = tuiRefreshOwner{generation: state.nextGeneration}
	state.refreshing = true
	state.refreshVisible = visible
	return state.owner
}

func (state *tuiRefreshState) current() tuiRefreshOwner { return state.owner }

func (state *tuiRefreshState) finish(owner tuiRefreshOwner) bool {
	if state.phase() != tuiRefreshRunning || owner != state.owner {
		return false
	}
	state.refreshing = false
	state.refreshVisible = false
	state.owner = tuiRefreshOwner{}
	return true
}
