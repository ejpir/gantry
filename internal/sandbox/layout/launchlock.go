package layout

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

// launchLockDirectory is deliberately not a valid sandbox name. It lives
// outside every replaceable per-sandbox directory, so RemoveAll(name) cannot
// unlink the lock that serializes that removal.
const launchLockDirectory = "@launch-locks"

// HoldLaunchLock takes the per-sandbox launch lock without blocking. The
// launcher holds it from before daemon spawn until readiness or process
// exit, so holders can rely on: no daemon is concurrently booting this
// sandbox. Stopped-sandbox configuration mutations (net-policy, resources,
// shares) take it to close the check-then-act race against a daemon that
// reads sandbox.json during boot.
func HoldLaunchLock(name string) (*os.File, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("invalid sandbox name %q", name)
	}
	dir := filepath.Join(Root(), launchLockDirectory)
	// CreateManagerDir protects the lock directory itself without touching
	// the sandbox root: start/daemon boot own the root's hardening, and a
	// control client re-protecting an existing root on Windows replaces its
	// DACL, breaking children that still hold ACEs inherited from it (this
	// made a stopped sandbox's own sandbox.json unreadable mid-command).
	if err := localsec.CreateManagerDir(dir); err != nil {
		return nil, fmt.Errorf("create launch-lock directory: %w", err)
	}

	path := filepath.Join(dir, name+".lock")
	lock, err := gutil.TryLockFile(path)
	if err != nil {
		return nil, fmt.Errorf("sandbox %q is already launching or its launch lock is unavailable: %w", name, err)
	}
	if err := localsec.SecureEndpoint(path); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("secure sandbox %q launch lock: %w", name, err)
	}
	return lock, nil
}
