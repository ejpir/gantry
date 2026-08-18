package manager

import (
	"context"
	"flag"
	"io"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/secret"
)

// stubLifecycle satisfies Lifecycle for the transport tests, which exercise
// routing, idempotency, decoding and event fan-out rather than any real VM.
// Resolve returns an empty configuration so create requests reach the
// transport's own bookkeeping; the tests that need real resolution live with
// the implementation, in the sandbox package.
type stubLifecycle struct{}

func (stubLifecycle) Resolve(*config.RunFlags, *flag.FlagSet) (config.RunConfig, []string, error) {
	return config.RunConfig{}, nil, nil
}

func (stubLifecycle) Launch(string, config.RunConfig, map[string]secret.Value, bool, io.Writer, io.Writer) int {
	return 0
}

func (stubLifecycle) Stop(string) error   { return nil }
func (stubLifecycle) Delete(string) error { return nil }

func (stubLifecycle) Exec(context.Context, string, ExecRequest) (ExecResult, error) {
	return ExecResult{}, nil
}
