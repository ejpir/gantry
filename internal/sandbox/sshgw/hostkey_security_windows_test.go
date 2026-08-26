//go:build windows

package sshgw

import (
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

func assertPrivateHostKey(t *testing.T, path string) {
	t.Helper()
	userSID, err := localsec.CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if err := localsec.VerifyPrivate(path, userSID, false); err != nil {
		t.Fatalf("host key DACL is not private: %v", err)
	}
}
