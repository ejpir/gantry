package oauthtokens

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRegistryMemory(t *testing.T) {
	r := New()
	set := TokenSet{Provider: "claude", AccessToken: "a1", RefreshToken: "r1", Expiry: time.Now().Add(time.Hour)}
	if err := r.Put(set); err != nil {
		t.Fatal(err)
	}
	got, ok := r.Get("claude")
	if !ok || got.AccessToken != "a1" || got.RefreshToken != "r1" {
		t.Fatalf("Get = %+v, %v", got, ok)
	}
	if providers := r.Providers(); len(providers) != 1 || providers[0] != "claude" {
		t.Fatalf("Providers = %v", providers)
	}
	if err := r.Delete("claude"); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Get("claude"); ok {
		t.Fatal("Get after Delete = found")
	}
}

func TestRegistryDiskSyncAndRestart(t *testing.T) {
	dir := t.TempDir()
	r1 := New()
	r1.AttachFile(dir)
	if err := r1.Put(TokenSet{Provider: "codex", AccessToken: "a1", RefreshToken: "r1", ClientID: "cid"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "oauth-tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode = %o, want 0600", info.Mode().Perm())
	}

	// A fresh registry over the same dir (the daemon-restart case)
	// recovers the session.
	r2 := New()
	r2.AttachFile(dir)
	got, ok := r2.Get("codex")
	if !ok || got.AccessToken != "a1" || got.RefreshToken != "r1" || got.ClientID != "cid" {
		t.Fatalf("recovered = %+v, %v", got, ok)
	}

	// Memory wins over the file for keys set before attach-load.
	r3 := New()
	_ = r3.Put(TokenSet{Provider: "codex", AccessToken: "newer"})
	r3.AttachFile(dir)
	got, _ = r3.Get("codex")
	if got.AccessToken != "newer" {
		t.Fatalf("memory did not win over disk: %+v", got)
	}

	// Delete syncs too: another restart sees the removal.
	if err := r2.Delete("codex"); err != nil {
		t.Fatal(err)
	}
	r4 := New()
	r4.AttachFile(dir)
	if _, ok := r4.Get("codex"); ok {
		t.Fatal("deleted set survived a simulated restart")
	}
}

func TestRefreshDue(t *testing.T) {
	now := time.Now()
	expiring := TokenSet{Provider: "p", RefreshToken: "r", Expiry: now.Add(30 * time.Minute)}
	due, ok := expiring.RefreshDue(now, 5*time.Minute)
	if !ok || due.Before(now.Add(24*time.Minute)) || due.After(now.Add(26*time.Minute)) {
		t.Fatalf("RefreshDue = %v, %v", due, ok)
	}
	// Inside the leeway: due immediately.
	soon := TokenSet{Provider: "p", RefreshToken: "r", Expiry: now.Add(time.Minute)}
	if due, ok := soon.RefreshDue(now, 5*time.Minute); !ok || !due.Equal(now) {
		t.Fatalf("RefreshDue inside leeway = %v, %v; want now", due, ok)
	}
	// Non-expiring or refresh-less sets never refresh.
	for _, set := range []TokenSet{
		{Provider: "p", RefreshToken: "r"},
		{Provider: "p", Expiry: now.Add(time.Hour)},
	} {
		if _, ok := set.RefreshDue(now, 5*time.Minute); ok {
			t.Fatalf("RefreshDue(%+v) = true, want false", set)
		}
	}
}

// The disk file holds real tokens — make sure nothing in this package
// stringifies a TokenSet into logs accidentally (no Stringer, and %v of
// the registry never embeds sets).
func TestRegistryDoesNotStringifyTokens(t *testing.T) {
	r := New()
	_ = r.Put(TokenSet{Provider: "claude", AccessToken: "canary-access", RefreshToken: "canary-refresh"})
	rendered := []string{
		strings.TrimSpace(strings.ReplaceAll(strings.Join(r.Providers(), ","), "\n", " ")),
	}
	for _, s := range rendered {
		if strings.Contains(s, "canary") {
			t.Fatalf("registry rendering leaked token material: %q", s)
		}
	}
}
