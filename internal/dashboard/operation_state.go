package dashboard

// tuiOperationPhase is the foreground-operation state owned by the dashboard.
// The operation is intentionally singular: while it is running, navigation may
// continue but no second mutating command is admitted.
type tuiOperationPhase uint8

const (
	tuiOperationIdle tuiOperationPhase = iota
	tuiOperationRunning
)

// tuiOperationState owns the foreground command label, target, streamed
// progress, and the post-create selection handoff. selectNext may outlive the
// running phase until a refresh observes the newly created sandbox.
type tuiOperationState struct {
	busyAction   string
	busyName     string
	busyProgress string
	selectNext   string
}

func (s *tuiOperationState) phase() tuiOperationPhase {
	if s.busyAction == "" {
		return tuiOperationIdle
	}
	return tuiOperationRunning
}

func (s *tuiOperationState) begin(action, name string, selectResult bool) bool {
	if action == "" || s.phase() != tuiOperationIdle {
		return false
	}
	s.busyAction = action
	s.busyName = name
	s.busyProgress = ""
	if selectResult {
		s.selectNext = name
	}
	return true
}

func (s *tuiOperationState) progress(line string) bool {
	if s.phase() != tuiOperationRunning {
		return false
	}
	s.busyProgress = line
	return true
}

func (s *tuiOperationState) finish(action, name string) bool {
	if s.phase() != tuiOperationRunning || action != s.busyAction || name != s.busyName {
		return false
	}
	s.busyAction = ""
	s.busyName = ""
	s.busyProgress = ""
	return true
}

func (s *tuiOperationState) clearSelection() { s.selectNext = "" }
