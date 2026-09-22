package operationstate

// Phase is the foreground-operation phase owned by the dashboard. The
// operation is intentionally singular: while it is running, navigation may
// continue but no second mutating command is admitted.
type Phase uint8

const (
	Idle Phase = iota
	Running
)

// Owner is the completion capability for one admitted operation. Generation
// prevents a delayed result for an earlier action with the same action and
// target from completing its replacement.
type Owner struct {
	generation uint64
	action     string
	name       string
}

func (owner Owner) Action() string { return owner.action }
func (owner Owner) Name() string   { return owner.name }

// State owns the foreground command label, target, streamed progress, and the
// post-create selection handoff. Selection may outlive the running phase until
// a refresh observes the newly created sandbox.
type State struct {
	action    string
	name      string
	progress  string
	selection string

	nextGeneration uint64
	owner          Owner
}

func (state *State) Phase() Phase {
	if state.action == "" {
		return Idle
	}
	return Running
}

func (state *State) Action() string    { return state.action }
func (state *State) Name() string      { return state.name }
func (state *State) Progress() string  { return state.progress }
func (state *State) Selection() string { return state.selection }

func (state *State) Begin(action, name string, selectResult bool) (Owner, bool) {
	if action == "" || state.Phase() != Idle {
		return Owner{}, false
	}
	state.nextGeneration++
	state.owner = Owner{generation: state.nextGeneration, action: action, name: name}
	state.action = action
	state.name = name
	state.progress = ""
	if selectResult {
		state.selection = name
	}
	return state.owner, true
}

func (state *State) SetProgress(owner Owner, line string) bool {
	if state.Phase() != Running || owner != state.owner {
		return false
	}
	state.progress = line
	return true
}

func (state *State) Finish(owner Owner) bool {
	if state.Phase() != Running || owner != state.owner {
		return false
	}
	state.owner = Owner{}
	state.action = ""
	state.name = ""
	state.progress = ""
	return true
}

func (state *State) ClearSelection() { state.selection = "" }
