// Package remote implements the client half of gantry's remote sandbox
// access (docs/remote-sandbox-access.md, milestone 2): named connection
// profiles, the TLS-verifying manager client, the `gantry remote` command,
// and the -remote dispatch target for everyday verbs.
//
// Security model: a remote is https://HOST:PORT plus a bearer token minted
// on the server (`gantry serve --mint-token`). The client always performs
// full TLS verification — disabling verification is not offered anywhere —
// with an optional CA bundle for self-signed servers and an optional exact
// leaf-fingerprint pin. A token is host-shell authority on the server, so
// it lives in a per-remote 0600 file and is refused when group/world
// readable, like an SSH private key. Profiles never contain token values.
package remote

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/remoteprofile"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

// Profile is one named remote manager. CACert is public material (the
// server's self-signed CA, when it uses one) and may live in the profile;
// the bearer token never does.
type Profile = remoteprofile.Profile

type storeFile struct {
	Remotes []Profile `json:"remotes"`
}

// baseDir is the client-side configuration root (~/.gantry). It mirrors the
// manager's GANTRY_HOME-derived base so tests and power users keep one tree.
func baseDir() string {
	if home := os.Getenv("GANTRY_HOME"); home != "" {
		return filepath.Dir(filepath.Clean(home))
	}
	return filepath.Dir(layout.Root())
}

func storePath() string { return filepath.Join(baseDir(), "remotes.json") }

func tokenDir() string { return filepath.Join(baseDir(), "remotes") }

func tokenPath(name string) string { return filepath.Join(tokenDir(), name+".token") }

// ValidateToken applies the same shape rule as the server's token file so a
// client-side typo is caught at add time rather than as a 403 later.
func ValidateToken(token string) error {
	if len(token) < 16 || len(token) > 256 {
		return fmt.Errorf("token must be 16-256 characters (got %d)", len(token))
	}
	for _, r := range token {
		if r < 0x21 || r > 0x7e {
			return fmt.Errorf("token contains non-printable characters")
		}
	}
	return nil
}

func validateProfile(profile Profile) error { return remoteprofile.Validate(profile) }

func loadStore() (storeFile, error) {
	data, err := os.ReadFile(storePath())
	if errors.Is(err, os.ErrNotExist) {
		return storeFile{}, nil
	}
	if err != nil {
		return storeFile{}, err
	}
	var store storeFile
	if err := json.Unmarshal(data, &store); err != nil {
		return storeFile{}, fmt.Errorf("parse %s: %w", storePath(), err)
	}
	names := make(map[string]bool)
	for _, profile := range store.Remotes {
		if err := validateProfile(profile); err != nil {
			return storeFile{}, fmt.Errorf("invalid remote profile: %w", err)
		}
		if names[profile.Name] {
			return storeFile{}, fmt.Errorf("duplicate remote name %q", profile.Name)
		}
		names[profile.Name] = true
	}
	return store, nil
}

func lockStore() (*os.File, error) {
	if err := localsec.CreateManagerDir(tokenDir()); err != nil {
		return nil, err
	}
	return gutil.TryLockFile(filepath.Join(tokenDir(), "store.lock"))
}

func saveStore(store storeFile) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(storePath(), append(data, '\n'), 0o600)
}

// List returns the configured profiles in declaration order.
func List() ([]Profile, error) {
	store, err := loadStore()
	if err != nil {
		return nil, err
	}
	return store.Remotes, nil
}

// Lookup finds one profile by name.
func Lookup(name string) (Profile, bool, error) {
	store, err := loadStore()
	if err != nil {
		return Profile{}, false, err
	}
	for _, profile := range store.Remotes {
		if profile.Name == name {
			return profile, true, nil
		}
	}
	return Profile{}, false, nil
}

// Add validates and persists a new profile plus its token. The token file is
// written before the profile so a crash never leaves a tokenless profile;
// a profile-save failure removes the orphaned token again.
func Add(profile Profile, token string) error {
	if err := validateProfile(profile); err != nil {
		return err
	}
	if err := ValidateToken(token); err != nil {
		return err
	}
	lock, err := lockStore()
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if _, exists, err := Lookup(profile.Name); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("remote %q already exists (remove it first with: gantry remote rm %s)", profile.Name, profile.Name)
	}
	if err := localsec.CreateManagerDir(tokenDir()); err != nil {
		return err
	}
	path := tokenPath(profile.Name)
	if err := atomicfile.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	if err := secureTokenFile(path); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("secure token file: %w", err)
	}
	store, err := loadStore()
	if err != nil {
		_ = os.Remove(tokenPath(profile.Name))
		return err
	}
	store.Remotes = append(store.Remotes, profile)
	if err := saveStore(store); err != nil {
		_ = os.Remove(tokenPath(profile.Name))
		return err
	}
	return nil
}

// Remove deletes a profile and its token file.
func Remove(name string) error {
	if err := layout.ValidateName(name); err != nil {
		return err
	}
	lock, err := lockStore()
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	store, err := loadStore()
	if err != nil {
		return err
	}
	kept := store.Remotes[:0]
	found := false
	for _, profile := range store.Remotes {
		if profile.Name == name {
			found = true
			continue
		}
		kept = append(kept, profile)
	}
	if !found {
		return fmt.Errorf("unknown remote %q", name)
	}
	store.Remotes = kept
	if err := saveStore(store); err != nil {
		return err
	}
	if err := os.Remove(tokenPath(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("profile removed, but the token file could not be: %w", err)
	}
	return nil
}

// Load resolves a profile and its token for dialing. Error text names the
// configured remotes so a mistyped -remote is self-explanatory.
func Load(name string) (Profile, string, error) {
	profile, found, err := Lookup(name)
	if err != nil {
		return Profile{}, "", err
	}
	if !found {
		store, _ := loadStore()
		names := make([]string, 0, len(store.Remotes))
		for _, p := range store.Remotes {
			names = append(names, p.Name)
		}
		if len(names) == 0 {
			return Profile{}, "", fmt.Errorf("unknown remote %q (none configured; add one with: gantry remote add %s https://HOST:PORT)", name, name)
		}
		return Profile{}, "", fmt.Errorf("unknown remote %q (configured: %s)", name, strings.Join(names, ", "))
	}
	token, err := LoadToken(name)
	if err != nil {
		return Profile{}, "", err
	}
	return profile, token, nil
}

// LoadToken reads a remote's token, refusing files other users can read:
// the token is a login credential, not configuration.
func LoadToken(name string) (string, error) {
	if err := layout.ValidateName(name); err != nil {
		return "", err
	}
	path := tokenPath(name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("no token for remote %q (expected %s; re-add with: gantry remote add %s URL --token-file FILE)", name, path, name)
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 258 {
		return "", fmt.Errorf("token file %s must be a regular file of at most 258 bytes", path)
	}
	if err := validateTokenFileSecurity(path, info); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimRight(string(data), "\r\n")
	if err := ValidateToken(token); err != nil {
		return "", fmt.Errorf("token file %s: %w", path, err)
	}
	return token, nil
}
