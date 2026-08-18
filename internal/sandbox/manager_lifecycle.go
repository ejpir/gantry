package sandbox

import (
	"context"
	"errors"
	"flag"
	"io"
	"strings"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/manager"
	"github.com/ejpir/gantry/internal/secret"
)

// managerLifecycle adapts this package's sandbox lifecycle to the manager
// API's transport-facing interface. The manager owns the error vocabulary its
// HTTP statuses are derived from, so the adapter translates the daemon's own
// sentinels into it rather than leaking them across the boundary.
type managerLifecycle struct{}

func (managerLifecycle) Resolve(flags *config.RunFlags, fs *flag.FlagSet) (config.RunConfig, []string, error) {
	// cachedOnly: an API request must never block on a network fetch.
	return resolveFlagsWithPolicy(flags, fs, nil, nil, true)
}

func (managerLifecycle) Launch(name string, cfg config.RunConfig, secrets map[string]secret.Value, replaceConfig bool, stdout, stderr io.Writer) int {
	return launchSandboxModeWithSpawnerTimingIO(name, cfg, secrets, replaceConfig, false, startSandboxDaemon, nil, stdout, stderr)
}

func (managerLifecycle) Stop(name string) error {
	err := stopSandbox(name)
	if errors.Is(err, errSandboxNotRunning) {
		return manager.ErrNotRunning
	}
	return err
}

// Delete is idempotent: deleteSandbox removes the tree, so repeating it is a
// no-op rather than an error.
func (managerLifecycle) Delete(name string) error { return deleteSandbox(name) }

func (managerLifecycle) Exec(ctx context.Context, name string, request manager.ExecRequest) (manager.ExecResult, error) {
	result, err := execSandboxCaptured(name, capturedExecRequest{
		Context:        ctx,
		Args:           request.Args,
		Cwd:            request.Cwd,
		Stdin:          strings.NewReader(request.Stdin),
		Timeout:        request.Timeout,
		MaxOutputBytes: request.MaxOutputBytes,
	})
	out := manager.ExecResult{
		ExitCode:  result.ExitCode,
		Output:    result.Output,
		Truncated: result.Truncated,
	}
	switch {
	case errors.Is(err, errCapturedExecTimeout):
		return out, errors.Join(manager.ErrExecTimeout, err)
	case errors.Is(err, errCapturedExecOutputLimit):
		return out, errors.Join(manager.ErrExecOutputLimit, err)
	}
	return out, err
}

// CmdServe runs the same-user local HTTP/JSON manager against this package's
// sandbox lifecycle.
func CmdServe(argv []string) int { return manager.Cmd(argv, managerLifecycle{}) }
