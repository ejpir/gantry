//go:build windows

package oauthtokens

import (
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

func TestRegistrySyncProtectsReplacementDACL(t *testing.T) {
	dir := t.TempDir()
	registry := New()
	registry.AttachFile(dir)
	if err := registry.Put(TokenSet{
		Provider:     "claude",
		AccessToken:  "access",
		RefreshToken: "refresh",
	}); err != nil {
		t.Fatal(err)
	}

	userSID, err := localsec.CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "oauth-tokens.json")
	if err := localsec.VerifyPrivate(path, userSID, false); err != nil {
		t.Fatalf("token file DACL: %v", err)
	}
}
