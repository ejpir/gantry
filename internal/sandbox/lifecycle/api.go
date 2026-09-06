// Package lifecycle defines the application contract shared by Gantry's
// command-line, dashboard, and HTTP adapters.
package lifecycle

import (
	"context"
	"errors"

	"github.com/ejpir/gantry/internal/sandbox/config"
)

type StartMode uint8

const (
	// Create refuses an existing saved sandbox.
	Create StartMode = iota
	// Replace preserves the historical CLI start behavior for stopped sandboxes.
	Replace
	// Resume reloads saved configuration under the launch lock.
	Resume
)

type StartRequest struct {
	Name       string
	Mode       StartMode
	Options    config.RunOptions
	CachedOnly bool
}

type StartResult struct {
	Name     string
	PID      int
	Warnings []string
}

// Progress is an operation event, not a line scraped from command output.
type Progress struct {
	Phase   string
	Message string
	Warning bool
}

type Observer func(Progress)

func (observer Observer) Emit(phase, message string) {
	if observer != nil {
		observer(Progress{Phase: phase, Message: message})
	}
}

type Service interface {
	// Cancellation before readiness aborts the uncommitted launch. After
	// readiness the persistent daemon belongs to the sandbox, not its caller.
	Start(context.Context, StartRequest, Observer) (StartResult, error)
}

var (
	ErrAlreadyExists  = errors.New("sandbox already exists")
	ErrAlreadyRunning = errors.New("sandbox is already running")
)
