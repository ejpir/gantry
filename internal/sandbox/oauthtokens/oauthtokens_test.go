package oauthtokens

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	if err := r1.Put(TokenSet{Provider: "codex", AccessToken: "a1", RefreshToken: "r1", IDToken: "id1", AccountID: "acct1", ClientID: "cid"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "oauth-tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Unix permission assertion only: Windows reports 0666 for
	// ACL-protected files (unix mode bits do not exist there), and the
	// user-profile ACL is what protects the file.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode = %o, want 0600", info.Mode().Perm())
	}

	// A fresh registry over the same dir (the daemon-restart case)
	// recovers the session.
	r2 := New()
	r2.AttachFile(dir)
	got, ok := r2.Get("codex")
	if !ok || got.AccessToken != "a1" || got.RefreshToken != "r1" || got.IDToken != "id1" || got.AccountID != "acct1" || got.ClientID != "cid" {
		t.Fatalf("recovered = %+v, %v", got, ok)
	}

	// Attaching after an in-memory operation still loads non-conflicting disk
	// keys, while memory wins for keys already held.
	r3 := New()
	_ = r3.Put(TokenSet{Provider: "claude", AccessToken: "newer"})
	r3.AttachFile(dir)
	if got, ok := r3.Get("codex"); !ok || got.AccessToken != "a1" {
		t.Fatalf("late attach did not load disk set: found=%v", ok)
	}
	if got, ok := r3.Get("claude"); !ok || got.AccessToken != "newer" {
		t.Fatalf("memory did not survive disk load: found=%v", ok)
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

func TestCorruptFileIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	// Genuinely corrupt: expiry as a bool (numeric would migrate; bool
	// is neither schema).
	bad := `[{"accessToken":"a","refreshToken":"r","expiry":true,"provider":"claude","clientId":"c"}]`
	if err := os.WriteFile(filepath.Join(dir, "oauth-tokens.json"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	r := New()
	r.AttachFile(dir)
	var logs []string
	r.SetLogger(func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	if got := r.Providers(); len(got) != 0 { // restoreRestart's path: loud
		t.Fatalf("corrupt file must not yield providers: %v", got)
	}
	if _, ok := r.Get("claude"); ok {
		t.Fatal("corrupt file must not yield a token set")
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "quarantined") {
		t.Fatalf("expected one loud quarantine line, got %v", logs)
	}
	if strings.HasPrefix(logs[0], "oauth tokens:") {
		t.Fatalf("logger message must not self-prefix (callback owns it): %q", logs[0])
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "oauth-tokens.json.corrupt-*"))
	if len(matches) != 1 {
		t.Fatalf("evidence file not quarantined: %v", matches)
	}
	// Custody recovers: a fresh Put writes a clean file.
	if err := r.Put(TokenSet{Provider: "claude", AccessToken: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Get("claude"); !ok {
		t.Fatal("registry should accept new tokens after quarantine")
	}
}

func TestLegacyNumericExpiryMigrates(t *testing.T) {
	dir := t.TempDir()
	legacy := `[{"accessToken":"a","refreshToken":"r","expiry":2000000000.164768,"provider":"claude","clientId":"c"}]` // float seconds, as early dev/mock runs wrote
	if err := os.WriteFile(filepath.Join(dir, "oauth-tokens.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	r := New()
	r.AttachFile(dir)
	var logs []string
	r.SetLogger(func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	set, ok := r.Get("claude")
	if !ok {
		t.Fatal("legacy numeric expiry must migrate, not quarantine")
	}
	if set.Expiry.Unix() != 2000000000 {
		t.Fatalf("expiry = %v", set.Expiry)
	}
	if ns := set.Expiry.Nanosecond(); ns < 160000000 || ns > 170000000 {
		t.Fatalf("fractional seconds lost: %v", set.Expiry)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "migrated legacy numeric expiry") {
		t.Fatalf("expected a migration line, got %v", logs)
	}
	// The file was rewritten in the current schema: RFC3339 string.
	b, _ := os.ReadFile(filepath.Join(dir, "oauth-tokens.json"))
	var raw []map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if _, isString := raw[0]["expiry"].(string); !isString {
		t.Fatalf("rewritten expiry should be a string: %s", b)
	}
	// No quarantine happened.
	matches, _ := filepath.Glob(filepath.Join(dir, "oauth-tokens.json.corrupt-*"))
	if len(matches) != 0 {
		t.Fatalf("unexpected quarantine: %v", matches)
	}
}
