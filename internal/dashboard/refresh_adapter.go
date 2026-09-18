package dashboard

import "github.com/ejpir/gantry/internal/dashboard/refreshstate"

type tuiRefreshOwner = refreshstate.Owner
type tuiRefreshState = refreshstate.State
type tuiRefreshPhase = refreshstate.Phase

const (
	tuiRefreshIdle    = refreshstate.Idle
	tuiRefreshRunning = refreshstate.Running
)

func newTUIRefreshState() tuiRefreshState { return refreshstate.New() }
