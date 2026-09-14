package remote

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ejpir/gantry/api/managerapi"
)

func TestRegisterStandaloneProbesAndNeverOverwrites(t *testing.T) {
	testHome(t)
	var calls atomic.Int32
	_, profile := stubManager(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(managerapi.Health{OK: true, Version: "test"})
	}))
	fingerprint, err := Register(t.Context(), profile, testToken)
	if err != nil || !strings.HasPrefix(fingerprint, "sha256:") {
		t.Fatalf("Register = %q %v", fingerprint, err)
	}
	if _, err := Register(t.Context(), profile, testToken); err == nil || calls.Load() != 1 {
		t.Fatal("duplicate probed/overwrote profile")
	}
	got, token, err := Load(profile.Name)
	if err != nil || got != profile || token != testToken {
		t.Fatalf("stored profile: %v", err)
	}
	raw, err := os.ReadFile(storePath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), testToken) {
		t.Fatal("token leaked to profile")
	}
	// No org configuration, receipt, IdP or catalog was needed.
}

func TestRegisterFailuresLeaveNoProfileOrToken(t *testing.T) {
	for _, mode := range []string{"bad token", "untrusted CA", "bad pin", "cancel", "hostile diagnostic"} {
		t.Run(mode, func(t *testing.T) {
			testHome(t)
			_, profile := stubManager(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "hostile diagnostic" {
					w.WriteHeader(500)
					_ = json.NewEncoder(w).Encode(managerapi.ErrorResponse{Error: testToken})
					return
				}
				_ = json.NewEncoder(w).Encode(managerapi.Health{OK: true})
			}))
			token := testToken
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "bad token":
				token = "different-token-0123456789"
			case "untrusted CA":
				profile.CACert = ""
			case "bad pin":
				profile.Fingerprint = "sha256:" + strings.Repeat("0", 64)
			case "cancel":
				cancel()
			}
			if _, err := Register(ctx, profile, token); err == nil || strings.Contains(err.Error(), token) {
				t.Fatalf("unsafe/missing refusal: %v", err)
			}
			if profiles, err := List(); err != nil || len(profiles) != 0 {
				t.Fatal("failed registration persisted profile")
			}
			if _, err := os.Stat(tokenPath(profile.Name)); !os.IsNotExist(err) {
				t.Fatal("failed registration persisted token")
			}
		})
	}
}

func TestConcurrentAddCannotReplaceToken(t *testing.T) {
	testHome(t)
	var successes atomic.Int32
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			if Add(Profile{Name: "team", URL: "https://example.com"}, testToken) == nil {
				successes.Add(1)
			}
		})
	}
	workers.Wait()
	if successes.Load() != 1 {
		t.Fatalf("accepted %d duplicate profiles", successes.Load())
	}
	if _, token, err := Load("team"); err != nil || token != testToken {
		t.Fatalf("concurrent add damaged token: %v", err)
	}
}

func TestReadCAIsBoundedAndRejectsNonFiles(t *testing.T) {
	dir := t.TempDir()
	for _, data := range []string{"invalid PEM", strings.Repeat("x", (64<<10)+1)} {
		path := filepath.Join(dir, "ca.pem")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadCA(path); err == nil {
			t.Fatal("invalid CA accepted")
		}
	}
	if _, err := ReadCA(dir); err == nil {
		t.Fatal("directory accepted as CA")
	}
}
