package dashboard

import "github.com/ejpir/gantry/internal/dashboard/operationstate"

type tuiOperationOwner = operationstate.Owner
type tuiOperationState = operationstate.State
type tuiOperationPhase = operationstate.Phase

const (
	tuiOperationIdle    = operationstate.Idle
	tuiOperationRunning = operationstate.Running
)
