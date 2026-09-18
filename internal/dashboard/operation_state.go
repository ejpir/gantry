package dashboard

// tuiOperationPhase is the foreground-operation state owned by the dashboard.
// The operation is intentionally singular: while it is running, navigation may
// continue but no second mutating command is admitted.
type tuiOperationPhase uint8

const (
	tuiOperationIdle tuiOperationPhase = iota
	tuiOperationRunning
)

// tuiOperationOwner is the completion capability for one admitted operation.
// generation prevents a delayed result for an earlier action with the same
// action and target from completing its replacement.
type tuiOperationOwner struct {
	generation uint64
	action     string
	name       string
}

// tuiOperationState owns the foreground command label, target, streamed
// progress, and the post-create selection handoff. selectNext may outlive the
// running phase until a refresh observes the newly created sandbox.
type tuiOperationState struct {
	busyAction   string
	busyName     string
	busyProgress string
	selectNext   string

	nextGeneration uint64
	owner          tuiOperationOwner
}

func (s *tuiOperationState) phase() tuiOperationPhase {
	if s.busyAction == "" {
		return tuiOperationIdle
	}
	return tuiOperationRunning
}

func (s *tuiOperationState) begin(action, name string, selectResult bool) (tuiOperationOwner, bool) {
	if action == "" || s.phase() != tuiOperationIdle {
		return tuiOperationOwner{}, false
	}
	s.nextGeneration++
	s.owner = tuiOperationOwner{generation: s.nextGeneration, action: action, name: name}
	s.busyAction = action
	s.busyName = name
	s.busyProgress = ""
	if selectResult {
		s.selectNext = name
	}
	return s.owner, true
}

func (s *tuiOperationState) progress(owner tuiOperationOwner, line string) bool {
	if s.phase() != tuiOperationRunning || owner != s.owner {
		return false
	}
	s.busyProgress = line
	return true
}

func (s *tuiOperationState) finish(owner tuiOperationOwner) bool {
	if s.phase() != tuiOperationRunning || owner != s.owner {
		return false
	}
	s.owner = tuiOperationOwner{}
	s.busyAction = ""
	s.busyName = ""
	s.busyProgress = ""
	return true
}

func (s *tuiOperationState) clearSelection() { s.selectNext = "" }
