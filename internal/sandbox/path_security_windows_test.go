//go:build windows

package sandbox

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCreateSandboxDirectoryInstallsProtectedDACL(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sandboxes")
	dir := filepath.Join(root, "dev")
	if err := createSandboxDirectory(dir); err != nil {
		t.Fatal(err)
	}
	userSID, err := currentWindowsUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateWindowsPath(root, userSID, false); err != nil {
		t.Fatalf("%s: %v", root, err)
	}
	if err := verifyPrivateWindowsPath(dir, userSID, true); err != nil {
		t.Fatalf("%s: %v", dir, err)
	}
}

func TestSecureLocalEndpointReplacesPermissiveDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctl.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(path)
	})

	permissive, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := permissive.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatal(err)
	}

	userSID, err := currentWindowsUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateWindowsPath(path, userSID, false); err == nil {
		t.Fatal("permissive endpoint DACL unexpectedly verified")
	}
	if err := secureLocalEndpoint(path); err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateWindowsPath(path, userSID, false); err != nil {
		t.Fatal(err)
	}
}

func TestSandboxLaunchLockInstallsProtectedDACL(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sandboxes")
	t.Setenv("GANTRY_HOME", root)
	lock, err := holdSandboxLaunchLock("dev")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()

	userSID, err := currentWindowsUserSID()
	if err != nil {
		t.Fatal(err)
	}
	lockDir := filepath.Join(root, launchLockDirectory)
	if err := verifyPrivateWindowsPath(root, userSID, false); err != nil {
		t.Fatalf("sandbox root: %v", err)
	}
	if err := verifyPrivateWindowsPath(lockDir, userSID, true); err != nil {
		t.Fatalf("launch-lock directory: %v", err)
	}
	if err := verifyPrivateWindowsPath(filepath.Join(lockDir, "dev.lock"), userSID, false); err != nil {
		t.Fatalf("launch-lock file: %v", err)
	}
}
