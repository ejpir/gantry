//go:build windows

package remote

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestLoadTokenRefusesPermissiveWindowsACL(t *testing.T) {
	testHome(t)
	addTestProfile(t, "cloud")
	path := tokenPath("cloud")

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

	if _, _, err := Load("cloud"); err == nil || !strings.Contains(err.Error(), "insecure Windows ACL") {
		t.Fatalf("Load with permissive token ACL = %v, want ACL error", err)
	}
}
