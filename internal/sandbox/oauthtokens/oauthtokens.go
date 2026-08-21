// Package oauthtokens is the host-side custody registry for OAuth token
// sets (docs/credential-brokering.md workstream 3). In custody mode the
// daemon exchanges the authorization code itself: the REFRESH token never
// enters the guest — the guest's auth file carries the current access
// token plus a sentinel refresh token, and a daemon-side loop refreshes
// ahead of expiry and pushes the fresh access token into the guest.
//
// Storage mirrors the reference implementation's SyncWithDisk semantics: memory is the fast path
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
	"sync"
	"time"
)

// TokenSet is one provider's token material held in custody.
type TokenSet struct {
	// AccessToken is pushed into the guest auth file and kept fresh by
	// the refresh loop.
	AccessToken string `json:"accessToken"`
	// RefreshToken stays host-side. May be empty for providers that
	// issue non-rotating refresh material or none at all.
	RefreshToken string `json:"refreshToken,omitempty"`
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
	r.path = filepath.Join(dir, "oauth-tokens.json")
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
		r.logf("oauth tokens: %v", err)
	}
	out := make([]string, 0, len(r.sets))
	for p := range r.sets {
		out = append(out, p)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func (r *Registry) loadLocked() error {
	if r.loaded || r.path == "" {
		r.loaded = true
		return nil
	}
	r.loaded = true
	b, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("load oauth tokens: %w", err)
	}
	var persisted []TokenSet
	if err := json.Unmarshal(b, &persisted); err != nil {
		return fmt.Errorf("parse %s: %w", r.path, err)
	}
	for _, set := range persisted {
		if _, exists := r.sets[set.Provider]; !exists {
			r.sets[set.Provider] = set
		}
	}
	return nil
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
	b, err := json.Marshal(sets)
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}
