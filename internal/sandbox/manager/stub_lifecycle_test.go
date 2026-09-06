package manager

import (
	"context"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"
)

// stubLifecycle satisfies Lifecycle for the transport tests, which exercise
// routing, idempotency, decoding and event fan-out rather than any real VM.
type stubLifecycle struct{}

func (stubLifecycle) Start(context.Context, lifecycle.StartRequest, lifecycle.Observer) (lifecycle.StartResult, error) {
	return lifecycle.StartResult{}, nil
}

func (stubLifecycle) Stop(string) error   { return nil }
func (stubLifecycle) Delete(string) error { return nil }

func (stubLifecycle) Exec(context.Context, string, ExecRequest) (ExecResult, error) {
	return ExecResult{}, nil
}
