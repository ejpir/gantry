package sandbox

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

// launchLockDirectory is deliberately not a valid sandbox name. It lives
// outside every replaceable per-sandbox directory, so RemoveAll(name) cannot
// unlink the lock that serializes that removal.
const launchLockDirectory = "@launch-locks"

func holdSandboxLaunchLock(name string) (*os.File, error) {
	if !layout.ValidName(name) {
		return nil, fmt.Errorf("invalid sandbox name %q", name)
	}
	dir := filepath.Join(layout.Root(), launchLockDirectory)
	// On Windows this creates protected DACLs on both the sandbox root and the
	// lock directory. On Unix the explicit hardening handles a pre-existing
	// directory created under a permissive umask.
	if err := localsec.CreateDir(dir); err != nil {
		return nil, fmt.Errorf("create launch-lock directory: %w", err)
	}
	if err := localsec.SecureDir(dir); err != nil {
		return nil, fmt.Errorf("secure launch-lock directory: %w", err)
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
