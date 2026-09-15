package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/controlcmd"
	"github.com/ejpir/gantry/internal/sandbox/manager"
)

// managerLifecycle adapts this package's sandbox lifecycle to the manager
// API's transport-facing interface. The manager owns the error vocabulary its
// HTTP statuses are derived from, so the adapter translates the daemon's own
// sentinels into it rather than leaking them across the boundary.
type managerLifecycle struct{ sandboxLifecycle }

func (managerLifecycle) Stop(name string) error {
	err := stopSandbox(name)
	if errors.Is(err, errSandboxNotRunning) {
		return manager.ErrNotRunning
	}
	return err
}

func (managerLifecycle) ApplyOrganizationPolicy(_ context.Context, name string, snapshot *policy.Config) error {
	return controlcmd.SetOrganizationPolicy(name, snapshot)
}

// RolloutOrganizationPolicy gives the local CLI the same controlled restart
// transaction used by manager API and policy-feed updates.
func RolloutOrganizationPolicy(name string, snapshot *policy.Config) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return manager.RolloutOrganizationPolicy(ctx, managerLifecycle{}, name, snapshot, true, nil)
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

// managerImage converts one cache entry to its wire shape.
func managerImage(meta *image.Meta) managerapi.Image {
	return managerapi.Image{
		Ref: meta.Ref, Digest: meta.Digest, Arch: meta.Arch,
		Size: meta.Size, Created: meta.Created,
	}
}

func (managerLifecycle) ListImages() ([]managerapi.Image, error) {
	metas := image.DefaultStore().List()
	images := make([]managerapi.Image, 0, len(metas))
	for _, meta := range metas {
		images = append(images, managerImage(meta))
	}
	return images, nil
}

// PullImage deliberately invokes the ordinary CLI in a short-lived process:
// registry credential helpers must never run inside the long-lived manager.
// The pull context belongs to the manager, not the requesting connection.
func (managerLifecycle) PullImage(ctx context.Context, ref, platform string, progress func(string)) (managerapi.Image, error) {
	arch := strings.TrimPrefix(platform, "linux/")
	if arch == "" {
		arch = hostGuestArch()
	}
	self, err := os.Executable()
	if err != nil {
		return managerapi.Image{}, err
	}
	command := exec.CommandContext(ctx, self, "image", "pull", "-remote=", "-platform", arch, ref)
	command.WaitDelay = 5 * time.Second
	command.Stdout = &pullProgressWriter{emit: progress}
	// Helper diagnostics can contain credential-helper output. Do not relay
	// them to the API; the operator can rerun the named helper on the host.
	if err := command.Run(); err != nil {
		return managerapi.Image{}, fmt.Errorf("image pull helper failed: %w; run `gantry image pull REF` on the manager host for diagnostics and `gantry image login REGISTRY` there for registry authentication", err)
	}
	store := image.DefaultStore()
	digest, found := store.LookupRef(ref, arch)
	if !found {
		return managerapi.Image{}, errors.New("image pull helper finished without a cached image")
	}
	meta, err := store.ReadMeta(digest)
	if err != nil {
		return managerapi.Image{}, err
	}
	return managerImage(meta), nil
}

// Only bounded CLI progress lines are retained; stderr is never captured.
// A malicious/verbose registry cannot grow the manager's memory without bound.
type pullProgressWriter struct {
	pending []byte
	emit    func(string)
}

func (w *pullProgressWriter) Write(data []byte) (int, error) {
	for _, b := range data {
		if b == '\n' || b == '\r' {
			if w.emit != nil && len(w.pending) != 0 {
				w.emit(string(w.pending))
			}
			w.pending = w.pending[:0]
		} else if len(w.pending) < 4096 && b >= 0x20 && b != 0x7f {
			w.pending = append(w.pending, b)
		}
	}
	return len(data), nil
}

func (managerLifecycle) DeleteImage(ref string) (managerapi.Image, error) {
	store := image.DefaultStore()
	var removed *image.Meta
	for _, meta := range store.List() {
		if meta.Ref == ref || meta.Digest == ref {
			removed = meta
			break
		}
	}
	if removed == nil {
		return managerapi.Image{}, manager.ErrImageNotFound
	}
	if err := store.Remove(ref); err != nil {
		return managerapi.Image{}, err
	}
	return managerImage(removed), nil
}

// CmdServe runs the same-user local HTTP/JSON manager against this package's
// sandbox lifecycle.
func CmdServe(argv []string) int { return manager.Cmd(argv, managerLifecycle{}) }
