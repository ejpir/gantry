//go:build windows

package sandbox

import (
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

func TestSandboxLaunchLockInstallsProtectedDACL(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sandboxes")
	t.Setenv("GANTRY_HOME", root)
	lock, err := holdSandboxLaunchLock("dev")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()

	userSID, err := localsec.CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	lockDir := filepath.Join(root, "@launch-locks")
	if err := localsec.VerifyPrivate(root, userSID, false); err != nil {
		t.Fatalf("sandbox root: %v", err)
	}
	if err := localsec.VerifyPrivate(lockDir, userSID, true); err != nil {
		t.Fatalf("launch-lock directory: %v", err)
	}
	if err := localsec.VerifyPrivate(filepath.Join(lockDir, "dev.lock"), userSID, false); err != nil {
		t.Fatalf("launch-lock file: %v", err)
	}
}
