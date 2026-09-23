// Package policy implements opt-in, host-owned organization policy using OPA.
// The host user is trusted. Signed snapshots establish provenance, not mandatory
// device enrollment. Rego is shipped with Gantry; v1 bundles contain data only.
package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/open-policy-agent/opa/v1/bundle"
)

const (
	MaxBundleBytes   = 256 << 10
	maxExpandedBytes = 2 << 20
	maxKeyBytes      = 16 << 10
)

// Config pins both the signed bundle and its host-selected public key in
// sandbox.json. Never reload a key from a potentially guest-writable share.
// No private key, login token, or secret is stored here.
type Config struct {
	Bundle    []byte `json:"bundle"`
	PublicKey string `json:"public_key"`
	Profile   string `json:"profile"`
}

func CloneConfig(config *Config) *Config {
	if config == nil {
		return nil
	}
	copy := *config
	copy.Bundle = bytes.Clone(config.Bundle)
	return &copy
}

type Document struct {
	Version      int                `json:"version"`
	Organization string             `json:"organization"`
	Revision     string             `json:"revision"`
	ExpiresAt    time.Time          `json:"expires_at"`
	Profiles     map[string]Profile `json:"profiles"`
}

type Profile struct {
	Rules   []Rule  `json:"rules"`
	Network Network `json:"network"`
}

type Network struct {
	Rules []netpol.GuardRule `json:"rules"`
	DNS   []string           `json:"dns"`
}

// Rule selectors are action-specific. Unknown/misplaced fields are rejected,
// not ignored. Name patterns support exact names or a single trailing '*'.
type Rule struct {
	ID     string `json:"id"`
	Effect string `json:"effect"`
	Action string `json:"action"`
	Path   string `json:"path,omitempty"`
	Server string `json:"server,omitempty"`
	Tool   string `json:"tool,omitempty"`
	Host   string `json:"host,omitempty"`
}

func ReadConfig(bundlePath, publicKeyPath, profile string) (*Config, error) {
	if bundlePath == "" && publicKeyPath == "" && profile == "" {
		return nil, nil
	}
	if bundlePath == "" || publicKeyPath == "" || profile == "" {
		return nil, fmt.Errorf("org-policy, org-policy-key and policy-profile must be supplied together")
	}
	raw, err := readLimitedFile(bundlePath, MaxBundleBytes)
	if err != nil {
		return nil, fmt.Errorf("organization bundle: %w", err)
	}
	key, err := readLimitedFile(publicKeyPath, maxKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("organization public key: %w", err)
	}
	config := &Config{Bundle: raw, PublicKey: string(key), Profile: profile}
	if _, _, err := verify(config); err != nil {
		return nil, err
	}
	return config, nil
}

func readLimitedFile(path string, limit int64) ([]byte, error) {
	// Reject non-regular inputs before opening (in particular, FIFOs). The
	// host-selected path is trusted; recheck the opened file and bound reads.
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("requires a regular file of at most %d bytes", limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err = file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("requires a regular file of at most %d bytes", limit)
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err == nil && int64(len(raw)) > limit {
		err = fmt.Errorf("file exceeds %d bytes", limit)
	}
	return raw, err
}

func verify(config *Config) (Document, Profile, error) {
	var document Document
	if config == nil {
		return document, Profile{}, fmt.Errorf("organization policy is not configured")
	}
	if !validID(config.Profile) {
		return document, Profile{}, fmt.Errorf("invalid organization policy configuration")
	}
	document, err := verifyDocument(config.Bundle, config.PublicKey)
	if err != nil {
		return document, Profile{}, err
	}
	profile, ok := document.Profiles[config.Profile]
	if !ok {
		return document, Profile{}, fmt.Errorf("policy profile %q does not exist", config.Profile)
	}
	// Empty arrays must remain arrays in Rego, never null.
	if profile.Rules == nil {
		profile.Rules = []Rule{}
	}
	if profile.Network.Rules == nil {
		profile.Network.Rules = []netpol.GuardRule{}
	}
	if profile.Network.DNS == nil {
		profile.Network.DNS = []string{}
	}
	for i := range profile.Network.Rules {
		if profile.Network.Rules[i].Ports == nil {
			profile.Network.Rules[i].Ports = []uint16{}
		}
	}
	return document, profile, nil
}

// VerifyBundle checks a signed bundle against publicKey and returns its
// validated document without selecting a profile. A policy service holds one
// bundle for every profile; hosts still verify their own profile on receipt.
func VerifyBundle(bundleBytes []byte, publicKey string) (Document, error) {
	return verifyDocument(bundleBytes, publicKey)
}

// ParseDocument validates root data.json exactly as activation does,
// including expiry. It establishes no trust in the data.
func ParseDocument(raw []byte) (Document, error) {
	return parseDocument(raw)
}

func verifyDocument(bundleBytes []byte, publicKey string) (Document, error) {
	var document Document
	if len(bundleBytes) == 0 || len(bundleBytes) > MaxBundleBytes || len(publicKey) > maxKeyBytes {
		return document, fmt.Errorf("invalid organization policy configuration")
	}
	block, rest := pem.Decode([]byte(publicKey))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return document, fmt.Errorf("policy key must be one PEM RSA public key")
	}
	var key any
	var err error
	switch block.Type {
	case "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		err = fmt.Errorf("only public keys are accepted")
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if err != nil || !ok || rsaKey.N.BitLen() < 2048 {
		return document, fmt.Errorf("policy verification requires an RSA public key of at least 2048 bits")
	}
	if err := preflightArchive(bundleBytes); err != nil {
		return document, err
	}
	verification := bundle.NewVerificationConfig(map[string]*bundle.KeyConfig{
		"gantry": {Key: publicKey, Algorithm: "RS256"},
	}, "gantry", "", nil)
	verified, err := bundle.NewReader(bytes.NewReader(bundleBytes)).
		WithSizeLimitBytes(maxExpandedBytes).
		WithBundleVerificationConfig(verification).Read()
	if err != nil {
		return document, fmt.Errorf("verify organization bundle: %w", err)
	}
	if len(verified.Modules) != 0 || len(verified.WasmModules) != 0 || len(verified.PlanModules) != 0 {
		return document, fmt.Errorf("v1 organization bundles must contain data only")
	}
	raw, err := json.Marshal(verified.Data)
	if err != nil {
		return document, err
	}
	return parseDocument(raw)
}

// Bound total decompression, count, types and names before OPA parses anything.
// Requiring root data.json also excludes ambiguous duplicate/overlapping data
// files and unsigned auxiliary files. No files are extracted to the host.
func preflightArchive(raw []byte) error {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("policy bundle gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	expanded, err := io.ReadAll(io.LimitReader(gz, maxExpandedBytes+1))
	if err != nil || len(expanded) > maxExpandedBytes {
		return fmt.Errorf("invalid or oversized policy archive")
	}
	reader := tar.NewReader(bytes.NewReader(expanded))
	seen := map[string]bool{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("policy bundle tar: %w", err)
		}
		name := strings.TrimPrefix(header.Name, "/")
		// tar.Reader normalizes legacy regular-file headers to TypeReg.
		if header.Typeflag != tar.TypeReg || seen[name] {
			return fmt.Errorf("policy bundle contains duplicate or non-regular entries")
		}
		switch name {
		case "data.json", ".manifest", ".signatures.json":
		default:
			return fmt.Errorf("unsupported policy bundle entry %q (v1 accepts root data.json only)", name)
		}
		seen[name] = true
	}
	if !seen["data.json"] || !seen[".signatures.json"] {
		return fmt.Errorf("organization bundle must contain signed data.json")
	}
	return nil
}

func decodeStrict(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func validID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._:-", c) {
			continue
		}
		return false
	}
	return true
}

func validPattern(value string) bool {
	if value == "*" {
		return true
	}
	return validID(strings.TrimSuffix(value, "*"))
}

func validateProfile(document Document, profile Profile) error {
	if len(profile.Rules) > 256 {
		return fmt.Errorf("too many authorization rules")
	}
	seen := map[string]bool{}
	for _, rule := range profile.Rules {
		if !validID(rule.ID) || seen[rule.ID] || rule.Effect != "allow" && rule.Effect != "deny" {
			return fmt.Errorf("invalid/duplicate rule ID or effect")
		}
		seen[rule.ID] = true
		switch rule.Action {
		case MountRead, MountWrite:
			if !filepath.IsAbs(rule.Path) || filepath.Clean(rule.Path) != rule.Path || len(rule.Path) > 4096 || rule.Server != "" || rule.Tool != "" || rule.Host != "" {
				return fmt.Errorf("rule %s: mount rules require only an absolute clean path", rule.ID)
			}
		case MCPList, MCPCall:
			if !validPattern(rule.Server) || !validPattern(rule.Tool) || rule.Path != "" || rule.Host != "" {
				return fmt.Errorf("rule %s: MCP tool rules require only server and tool patterns", rule.ID)
			}
		case MCPConnect:
			if !validPattern(rule.Server) || rule.Tool != "" || rule.Path != "" || rule.Host != "" {
				return fmt.Errorf("rule %s: MCP connection rules require only a server pattern", rule.ID)
			}
		case CredentialUse:
			if !netpol.ValidGuardDomain(rule.Host) || rule.Path != "" || rule.Server != "" || rule.Tool != "" {
				return fmt.Errorf("rule %s: credential rules require only a host pattern", rule.ID)
			}
		default:
			return fmt.Errorf("rule %s: unsupported action %q", rule.ID, rule.Action)
		}
	}
	guard := netpol.GuardSpec{Organization: document.Organization, Revision: document.Revision, ExpiresAt: document.ExpiresAt, Rules: profile.Network.Rules, DNS: profile.Network.DNS}
	if err := netpol.ValidateGuard(guard); err != nil {
		return err
	}
	for _, rule := range profile.Network.Rules {
		if !validID(rule.ID) || seen[rule.ID] {
			return fmt.Errorf("invalid/duplicate network rule ID")
		}
		seen[rule.ID] = true
	}
	return nil
}
