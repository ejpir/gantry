// Package oauthtokens is the host-side custody registry for OAuth token
// sets (docs/credential-brokering.md workstream 3). In custody mode the
// daemon exchanges the authorization code itself: the REFRESH token never
// enters the guest — the guest's auth file carries the current access
// token plus a sentinel refresh token, and a daemon-side loop refreshes
// ahead of expiry and pushes the fresh access token into the guest.
//
// Storage mirrors sbx's SyncWithDisk semantics: memory is the fast path
// and the source of truth while the daemon runs; an optional 0600 file
// under the sandbox directory is the recovery path for daemon restarts,
// never the other way around.
//
// TokenSets are secret material. AccessToken/RefreshToken are plain
// strings (they must serialize for disk sync and guest file writes), so
// this package never logs them and tests must not print them either; the
// audit story stays with the broker, which logs names and decisions only.
package oauthtokens

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

// TokenSet is one provider's token material held in custody.
type TokenSet struct {
	// AccessToken is pushed into the guest auth file and kept fresh by
	// the refresh loop.
	AccessToken string `json:"accessToken"`
	// RefreshToken stays host-side. May be empty for providers that
	// issue non-rotating refresh material or none at all.
	RefreshToken string `json:"refreshToken,omitempty"`
	// IDToken and AccountID are required to render Codex's auth.json. The ID
	// token is copied into that guest file; the refresh token remains host-only.
	IDToken   string `json:"idToken,omitempty"`
	AccountID string `json:"accountId,omitempty"`
	// Expiry is the access token's expiry; zero means non-expiring.
	Expiry time.Time `json:"expiry,omitempty"`
	// Provider is the registry key ("claude", "codex", ...).
	Provider string `json:"provider"`
	// ClientID is the public OAuth client_id the flow ran under — needed
	// for refreshes after a daemon restart.
	ClientID string `json:"clientId,omitempty"`
}

// RefreshDue reports when the next refresh should happen: leeway before
// Expiry, or false for non-expiring / non-refreshable sets.
func (t TokenSet) RefreshDue(now time.Time, leeway time.Duration) (time.Time, bool) {
	if t.RefreshToken == "" || t.Expiry.IsZero() {
		return time.Time{}, false
	}
	due := t.Expiry.Add(-leeway)
	if due.Before(now) {
		return now, true
	}
	return due, true
}

// Registry holds token sets keyed by provider for ONE sandbox. It is
// in-memory first; AttachFile adds 0600 disk sync so a daemon restart
// (which keeps the same sandbox directory) recovers live sessions.
type Registry struct {
	mu     sync.Mutex
	now    func() time.Time
	logf   func(string, ...any)
	sets   map[string]TokenSet
	path   string // "" = memory only
	loaded bool
}

// New returns an in-memory registry.
func New() *Registry {
	return &Registry{now: time.Now, sets: map[string]TokenSet{}}
}

// SetLogger routes load-error diagnostics (corrupt token file) to logf.
func (r *Registry) SetLogger(logf func(string, ...any)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logf = logf
}

// AttachFile points the registry at a 0600 JSON file; the next operation
// lazily loads any persisted sets (memory wins on key conflicts — a set
// captured after the last sync is newer than the file). The directory is
// created 0700.
func (r *Registry) AttachFile(dir string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	path := filepath.Join(dir, "oauth-tokens.json")
	if r.path != path {
		r.loaded = false
	}
	r.path = path
}

// Put stores or replaces a provider's token set and syncs to disk.
func (r *Registry) Put(set TokenSet) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.loadLocked(); err != nil {
		return err
	}
	r.sets[set.Provider] = set
	return r.syncLocked()
}

// Get returns the current set for provider.
func (r *Registry) Get(provider string) (TokenSet, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.loadLocked(); err != nil {
		return TokenSet{}, false
	}
	set, ok := r.sets[provider]
	return set, ok
}

// Delete removes a provider's set and syncs.
func (r *Registry) Delete(provider string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.loadLocked(); err != nil {
		return err
	}
	delete(r.sets, provider)
	return r.syncLocked()
}

// Providers lists the providers currently held (sorted for determinism).
// A load error is reported through logf (may be nil): silently treating a
// corrupt token file as "no sessions" would strand refresh loops.
func (r *Registry) Providers() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.loadLocked(); err != nil && r.logf != nil {
		r.logf("%v", err) // the logger callback owns the "oauth tokens:" prefix
	}
	out := make([]string, 0, len(r.sets))
	for p := range r.sets {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (r *Registry) loadLocked() error {
	if r.loaded || r.path == "" {
		r.loaded = true
		return nil
	}
	r.loaded = true
	info, err := os.Lstat(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect oauth tokens: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return r.quarantineLocked(fmt.Errorf("token store is not a regular file"))
	}
	if info.Size() > maxTokenFileBytes {
		return r.quarantineLocked(fmt.Errorf("token store exceeds %d bytes", maxTokenFileBytes))
	}
	if err := localsec.SecureRegularFile(r.path); err != nil {
		return r.quarantineLocked(fmt.Errorf("insecure token store: %w", err))
	}
	if err := os.Chmod(r.path, 0o600); err != nil {
		return fmt.Errorf("secure oauth tokens: %w", err)
	}
	b, err := os.ReadFile(r.path)
	if err != nil {
		return fmt.Errorf("load oauth tokens: %w", err)
	}
	var persisted []persistedSet
	if err := json.Unmarshal(b, &persisted); err != nil {
		return r.quarantineLocked(err)
	}
	migrated := false
	for _, ps := range persisted {
		exp, legacy, err := ps.expiryTime()
		if err != nil {
			return r.quarantineLocked(fmt.Errorf("provider %s: %w", ps.Provider, err))
		}
		if legacy {
			migrated = true
		}
		set := TokenSet{AccessToken: ps.AccessToken, RefreshToken: ps.RefreshToken,
			IDToken: ps.IDToken, AccountID: ps.AccountID, Expiry: exp,
			Provider: ps.Provider, ClientID: ps.ClientID}
		if _, exists := r.sets[set.Provider]; !exists {
			r.sets[set.Provider] = set
		}
	}
	if migrated {
		// Dev-build artifact: expiry was serialized as a unix number.
		// Accept it, say so, and rewrite the file in the current schema.
		if r.logf != nil {
			r.logf("migrated legacy numeric expiry in %s — rewriting", filepath.Base(r.path))
		}
		if err := r.syncLocked(); err != nil {
			return fmt.Errorf("rewrite migrated token file: %w", err)
		}
	}
	return nil
}

// persistedSet mirrors TokenSet on disk but keeps Expiry raw so legacy
// numeric encodings (early dev builds) can be migrated instead of
// quarantined.
const maxTokenFileBytes = 4 << 20

type persistedSet struct {
	AccessToken  string          `json:"accessToken"`
	RefreshToken string          `json:"refreshToken,omitempty"`
	IDToken      string          `json:"idToken,omitempty"`
	AccountID    string          `json:"accountId,omitempty"`
	Expiry       json.RawMessage `json:"expiry,omitempty"`
	Provider     string          `json:"provider"`
	ClientID     string          `json:"clientId,omitempty"`
}

// expiryTime parses expiry as RFC3339 (current schema) or unix seconds
// (legacy); the second return value reports the legacy form.
func (ps persistedSet) expiryTime() (time.Time, bool, error) {
	if len(ps.Expiry) == 0 || string(ps.Expiry) == "null" {
		return time.Time{}, false, nil
	}
	var s string
	if err := json.Unmarshal(ps.Expiry, &s); err == nil {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Time{}, false, fmt.Errorf("expiry %q is not RFC3339: %w", s, err)
		}
		return t, false, nil
	}
	var n int64
	if err := json.Unmarshal(ps.Expiry, &n); err == nil {
		return time.Unix(n, 0), true, nil
	}
	// Early dev/mock runs wrote float seconds (python time.time()).
	var f float64
	if err := json.Unmarshal(ps.Expiry, &f); err == nil {
		sec := int64(f)
		return time.Unix(sec, int64((f-float64(sec))*1e9)), true, nil
	}
	return time.Time{}, false, fmt.Errorf("expiry is neither an RFC3339 string nor unix seconds")
}

// quarantineLocked moves an unparseable token file aside and continues
// with an empty registry rather than wedging custody forever. Loud by
// contract: the caller audits the returned error, and the evidence file
// is preserved for inspection.
func (r *Registry) quarantineLocked(parseErr error) error {
	quarantine := fmt.Sprintf("%s.corrupt-%d", r.path, time.Now().Unix())
	if renErr := os.Rename(r.path, quarantine); renErr != nil {
		return fmt.Errorf("parse %s: %w (quarantine to %s failed: %v)", r.path, parseErr, quarantine, renErr)
	}
	return fmt.Errorf("parse %s: %w — quarantined to %s; custody continues empty (re-login to repopulate)",
		r.path, parseErr, filepath.Base(quarantine))
}

// syncLocked rewrites the file atomically-ish (write temp + rename) with
// 0600 permissions. No-op when memory-only. A sync failure is reported to
// the caller: custody continues in memory, but the caller should log that
// restart durability is uncertain.
func (r *Registry) syncLocked() error {
	if r.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	sets := make([]TokenSet, 0, len(r.sets))
	for _, set := range r.sets {
		sets = append(sets, set)
	}
	sort.Slice(sets, func(i, j int) bool { return sets[i].Provider < sets[j].Provider })
	b, err := json.Marshal(sets)
	if err != nil {
		return err
	}
	if err := atomicfile.WriteFile(r.path, b, 0o600); err != nil {
		return err
	}
	// Atomic replacement creates a new filesystem object. On Windows that
	// object may inherit its parent DACL even when the previous token file was
	// protected, so validate and harden the replacement before reporting a
	// durable sync. The sandbox directory is already private, preventing an
	// exposure window between rename and this check.
	if err := localsec.SecureRegularFile(r.path); err != nil {
		return fmt.Errorf("secure oauth tokens: %w", err)
	}
	return os.Chmod(r.path, 0o600)
}
