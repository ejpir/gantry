package orgauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/orgauth"
	"github.com/ejpir/gantry/internal/orgauth/testidp"
)

func TestReceiptPersistenceExpiryAndLogoutWithoutTokens(t *testing.T) {
	idp, path := fixture(t)
	trusted, err := orgauth.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := orgauth.Login(ctx, trusted, "", idp.Visit)
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(t.TempDir(), "sessions")
	if err := orgauth.SaveSession(store, s); err != nil {
		t.Fatal(err)
	}
	loaded, err := orgauth.LoadSession(store, s.Organization)
	if err != nil || loaded.Subject != s.Subject || !bytes.Equal(loaded.Policy.Bundle, s.Policy.Bundle) {
		t.Fatalf("receipt round trip failed: %v", err)
	}
	entries, err := os.ReadDir(store)
	if err != nil || len(entries) != 1 {
		t.Fatalf("unexpected store contents: %v", err)
	}
	file := filepath.Join(store, entries[0].Name())
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range append(idp.Secrets(), "access_token", "refresh_token", "id_token", "code_verifier", "example-developers") {
		if strings.Contains(string(raw), secret) {
			t.Fatal("receipt contains credentials or groups")
		}
	}
	if runtime.GOOS != "windows" {
		for path, mode := range map[string]os.FileMode{store: 0o700, file: 0o600} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("insecure receipt permissions: %v", err)
			}
		}
	}
	s.ExpiresAt = time.Now().Add(-time.Second)
	if err := orgauth.SaveSession(store, s); err == nil {
		t.Fatal("expired receipt saved")
	}
	after, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("failed save replaced existing receipt")
	}
	expired, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, expired, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := orgauth.LoadSession(store, s.Organization); err == nil {
		t.Fatal("expired receipt loaded")
	}
	for range 2 {
		if err := orgauth.Logout(store, testidp.Organization); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := orgauth.LoadSession(store, s.Organization); err == nil {
		t.Fatal("logged-out receipt loaded")
	}
	if err := orgauth.Logout(store, "../elsewhere"); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestReceiptStoreRejectsSymlinks(t *testing.T) {
	idp, path := fixture(t)
	trusted, err := orgauth.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := orgauth.Login(ctx, trusted, "", idp.Visit)
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(t.TempDir(), "sessions")
	target := t.TempDir()
	if err := os.Symlink(target, store); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := orgauth.SaveSession(store, s); err == nil {
		t.Fatal("symlink store accepted")
	}
	if err := os.Remove(store); err != nil {
		t.Fatal(err)
	}
	if err := orgauth.SaveSession(store, s); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(store)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(store, files[0].Name())
	if err := os.Rename(file, filepath.Join(target, "receipt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(target, "receipt"), file); err != nil {
		t.Fatal(err)
	}
	if _, err := orgauth.LoadSession(store, s.Organization); err == nil {
		t.Fatal("symlink receipt read")
	}
	if err := orgauth.SaveSession(store, s); err == nil {
		t.Fatal("symlink receipt replaced")
	}
}
