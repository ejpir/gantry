package refreshstate

type Phase uint8

const (
	Idle Phase = iota
	Running
)

// Owner identifies the snapshot request that may publish dashboard rows. It
// prevents a slow pre-operation refresh from replacing a newer post-operation
// snapshot.
type Owner struct{ generation uint64 }

type State struct {
	refreshing     bool
	visible        bool
	nextGeneration uint64
	owner          Owner
}

func New() State {
	var state State
	state.Restart(false)
	return state
}

func (state *State) Phase() Phase {
	if state.refreshing {
		return Running
	}
	return Idle
}

func (state *State) Refreshing() bool { return state.refreshing }
func (state *State) Visible() bool    { return state.visible }
func (state *State) Current() Owner   { return state.owner }

func (state *State) Begin(visible bool) (Owner, bool) {
	if state.Phase() != Idle {
		return Owner{}, false
	}
	return state.Restart(visible), true
}

func (state *State) Restart(visible bool) Owner {
	state.nextGeneration++
	state.owner = Owner{generation: state.nextGeneration}
	state.refreshing = true
	state.visible = visible
	return state.owner
}

func (state *State) Finish(owner Owner) bool {
	if state.Phase() != Running || owner != state.owner {
		return false
	}
	state.refreshing = false
	state.visible = false
	state.owner = Owner{}
	return true
}
