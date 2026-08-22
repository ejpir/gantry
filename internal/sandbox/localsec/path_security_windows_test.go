//go:build windows

package localsec

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
	if err := CreateDir(dir); err != nil {
		t.Fatal(err)
	}
	userSID, err := CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrivate(root, userSID, false); err != nil {
		t.Fatalf("%s: %v", root, err)
	}
	if err := VerifyPrivate(dir, userSID, true); err != nil {
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

	userSID, err := CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrivate(path, userSID, false); err == nil {
		t.Fatal("permissive endpoint DACL unexpectedly verified")
	}
	if err := SecureEndpoint(path); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrivate(path, userSID, false); err != nil {
		t.Fatal(err)
	}
}

func TestSecureRegularFileReplacesPermissiveDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gantry-guest.exe")
	if err := os.WriteFile(path, []byte("guest helper"), 0o666); err != nil {
		t.Fatal(err)
	}

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

	userSID, err := CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrivate(path, userSID, false); err == nil {
		t.Fatal("permissive file DACL unexpectedly verified")
	}
	if err := SecureRegularFile(path); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrivate(path, userSID, false); err != nil {
		t.Fatal(err)
	}
}
