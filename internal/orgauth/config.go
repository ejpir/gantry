// Package orgauth authenticates a host user against an explicitly trusted OIDC
// issuer and selects an organization policy through host-owned group mappings.
// It does not provide mandatory enrollment, guest OAuth, or a token cache.
package orgauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ejpir/gantry/internal/policy"
)

// Config is trusted host configuration, never downloaded from an ID token or
// inferred from an email address. Paths are relative to the config file.
type Config struct {
	Version       int               `json:"version"`
	Organization  string            `json:"organization"`
	Issuer        string            `json:"issuer"`
	ClientID      string            `json:"client_id"`
	RedirectPort  uint16            `json:"redirect_port,omitempty"`
	Scopes        []string          `json:"scopes,omitempty"`
	GroupClaim    string            `json:"group_claim"`
	GroupProfiles map[string]string `json:"group_profiles"`
	Bundle        string            `json:"bundle"`
	PublicKey     string            `json:"public_key"`
	CAFile        string            `json:"ca_file,omitempty"`
	RemoteCatalog *CatalogConfig    `json:"remote_catalog,omitempty"`
}

// ProviderConfig is a validated, pinned login configuration. No source files
// are reloaded during the browser round trip.
type ProviderConfig struct {
	config    Config
	snapshot  *policy.Config
	ca        []byte
	catalogCA []byte
}

func LoadConfig(path string) (*ProviderConfig, error) {
	raw, err := readRegular(path, 64<<10)
	if err != nil {
		return nil, fmt.Errorf("organization configuration: %w", err)
	}
	var c Config
	if err := strictJSON(raw, &c); err != nil {
		return nil, fmt.Errorf("invalid organization configuration")
	}
	if c.Version != 1 || !identifier(c.Organization) || !text(c.ClientID, 256) || !text(c.GroupClaim, 256) || len(c.GroupProfiles) == 0 || len(c.GroupProfiles) > 128 || len(c.Scopes) > 16 {
		return nil, fmt.Errorf("configuration requires version 1, organization, client_id, group_claim and 1..128 group_profiles")
	}
	if err := validateCatalogConfig(c.RemoteCatalog); err != nil {
		return nil, err
	}
	issuer, err := httpsURL(c.Issuer)
	if err != nil || issuer.RawQuery != "" || issuer.ForceQuery {
		return nil, fmt.Errorf("issuer must be an HTTPS URL without credentials, query or fragment")
	}
	for _, scope := range c.Scopes {
		if !text(scope, 128) || strings.ContainsAny(scope, " \"\\") || scope == "offline_access" {
			return nil, fmt.Errorf("invalid scope; offline_access is not supported (no refresh tokens)")
		}
	}
	profiles := make([]string, 0, len(c.GroupProfiles))
	for group, profile := range c.GroupProfiles {
		if !text(group, 256) || !identifier(profile) {
			return nil, fmt.Errorf("invalid group-to-profile mapping")
		}
		profiles = append(profiles, profile)
	}
	slices.Sort(profiles)
	profiles = slices.Compact(profiles)
	resolve := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(filepath.Dir(path), p)
	}
	snapshot, err := policy.ReadConfig(resolve(c.Bundle), resolve(c.PublicKey), profiles[0])
	if err != nil {
		return nil, fmt.Errorf("organization policy: %w", err)
	}
	if snapshot == nil {
		return nil, fmt.Errorf("organization configuration requires a signed bundle and public key")
	}
	for _, profile := range profiles {
		candidate := policy.CloneConfig(snapshot)
		candidate.Profile = profile
		engine, err := policy.New(candidate, nil)
		if err != nil {
			return nil, fmt.Errorf("mapped policy profile: %w", err)
		}
		if engine.Info().Organization != c.Organization {
			return nil, fmt.Errorf("signed policy organization does not match login configuration")
		}
	}
	var ca []byte
	if c.CAFile != "" {
		ca, err = readRegular(resolve(c.CAFile), 64<<10)
		if err != nil {
			return nil, fmt.Errorf("OIDC CA file: %w", err)
		}
	}
	var catalogCA []byte
	if c.RemoteCatalog != nil && c.RemoteCatalog.CAFile != "" {
		catalogCA, err = readRegular(resolve(c.RemoteCatalog.CAFile), 64<<10)
		if err != nil {
			return nil, fmt.Errorf("remote catalog CA file is unavailable")
		}
	}
	return &ProviderConfig{config: c, snapshot: snapshot, ca: ca, catalogCA: catalogCA}, nil
}

func identifier(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return s != "." && s != ".."
}

func text(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func httpsURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || strings.ContainsRune(raw, '#') || u.Opaque != "" {
		return nil, fmt.Errorf("requires an HTTPS URL without credentials or fragment")
	}
	return u, nil
}

func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("requires a regular file of at most %d bytes (no symlinks)", limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("requires a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, fmt.Errorf("file read failed or exceeds %d bytes", limit)
	}
	return raw, nil
}

func strictJSON(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
