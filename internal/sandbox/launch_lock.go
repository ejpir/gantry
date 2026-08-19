package sandbox

import (
	"os"

	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// holdSandboxLaunchLock keeps the historical package-local name; the lock
// itself lives in layout so configuration clients (controlcmd) can take the
// same lock without importing the orchestration facade.
func holdSandboxLaunchLock(name string) (*os.File, error) {
	return layout.HoldLaunchLock(name)
}
