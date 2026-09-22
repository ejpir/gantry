package manager

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/sandbox/manager/runtimeowner"
)

func prepareManagerState(plan servePlan, owner *runtimeowner.Owner) (string, error) {
	lockBase := managerLockBase(plan)
	if err := ensureManagerListenerRoots(plan); err != nil {
		return "", err
	}
	if err := localsec.CreateManagerDir(lockBase); err != nil {
		return "", fmt.Errorf("secure manager directory: %w", err)
	}
	stateDir := filepath.Join(lockBase, "manager-state")
	if err := localsec.CreateManagerDir(stateDir); err != nil {
		return "", fmt.Errorf("create manager state directory: %w", err)
	}
	lock, err := layout.HoldLock(stateDir)
	if err != nil {
		return "", fmt.Errorf("another manager holds the state lock: %w", err)
	}
	if err := owner.SetLock(lock); err != nil {
		_ = lock.Close()
		return "", err
	}
	return stateDir, nil
}

// The lock directory derives from the first unix listener (historical
// behavior) or the manager base for TLS-only plans.
func managerLockBase(plan servePlan) string {
	for _, spec := range plan.listeners {
		if spec.network == "unix" {
			return filepath.Dir(spec.address)
		}
	}
	return managerBaseDir()
}

func ensureManagerListenerRoots(plan servePlan) error {
	for _, spec := range plan.listeners {
		if isDefaultManagerSocket(spec) {
			// Secure each predictable fallback component before MkdirAll can
			// traverse the default application root.
			if err := layout.EnsureRoot(); err != nil {
				return err
			}
		}
	}
	return nil
}

func isDefaultManagerSocket(spec listenSpec) bool {
	return spec.network == "unix" &&
		os.Getenv("GANTRY_MANAGER_SOCKET") == "" &&
		filepath.Clean(spec.address) == filepath.Clean(SocketPath())
}
