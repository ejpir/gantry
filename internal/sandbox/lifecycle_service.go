package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"
)

// NewLifecycleService constructs the application service without doing I/O.
func NewLifecycleService() lifecycle.Service { return sandboxLifecycle{} }

type sandboxLifecycle struct{ milestone func(string) }

func (service sandboxLifecycle) Start(ctx context.Context, request lifecycle.StartRequest, observer lifecycle.Observer) (lifecycle.StartResult, error) {
	result := lifecycle.StartResult{Name: request.Name}
	if err := layout.ValidateName(request.Name); err != nil {
		return result, err
	}
	if request.Mode > lifecycle.Resume {
		return result, fmt.Errorf("invalid start mode %d", request.Mode)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	lock, err := holdSandboxLaunchLock(request.Name)
	if err != nil {
		return result, err
	}
	defer func() { _ = lock.Close() }()
	if service.milestone != nil {
		service.milestone("launcher launch lock acquired")
	}
	if request.Mode == lifecycle.Create {
		if _, err := os.Stat(filepath.Join(layout.Dir(request.Name), "sandbox.json")); err == nil {
			return result, fmt.Errorf("%w: %q", lifecycle.ErrAlreadyExists, request.Name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return result, err
		}
	}
	if _, alive := layout.PID(request.Name); alive || layout.LockHeld(layout.Dir(request.Name)) {
		return result, fmt.Errorf("%w: %q", lifecycle.ErrAlreadyRunning, request.Name)
	}
	var resolved resolvedRun
	if request.Mode == lifecycle.Resume {
		resolved.Config, resolved.Secrets, err = config.ReadSandboxForLaunch(layout.Dir(request.Name), os.LookupEnv)
		if err != nil {
			return result, fmt.Errorf("sandbox %q has no valid saved configuration: %w", request.Name, err)
		}
	} else {
		options := request.Options
		options.Name = request.Name
		resolved, err = resolveRunOptions(ctx, options, func(format string, args ...any) {
			observer.Emit("prepare", fmt.Sprintf(format, args...))
		}, service.milestone, request.CachedOnly)
		result.Warnings = resolved.Warnings
		if err != nil {
			return result, err
		}
		if count := len(resolved.Secrets) + len(resolved.Config.SecretSources); count > 0 && resolved.Config.Net && resolved.Config.NetPol == "" {
			resolved.Warnings = append(resolved.Warnings, fmt.Sprintf("%d secret(s) injected with the default egress policy (internet allowed). Consider -net-policy with a domain allowlist so an injected agent cannot send them anywhere.", count))
		}
	}
	result.Warnings = resolved.Warnings
	if service.milestone != nil {
		service.milestone("launcher secrets resolved")
	}
	for _, warning := range resolved.Warnings {
		if observer != nil {
			observer(lifecycle.Progress{Phase: "prepare", Message: warning, Warning: true})
		}
	}
	result.PID, err = launchSandboxLockedCore(ctx, request.Name, resolved.Config, resolved.Secrets,
		request.Mode != lifecycle.Resume, false, startSandboxDaemon, service.milestone, observer)
	return result, err
}
