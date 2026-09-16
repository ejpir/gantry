package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ejpir/gantry/internal/oauthprovider"
)

// ReadOAuthProvider snapshots public metadata at launch. The daemon never
// reopens the input file, so a later guest edit cannot redirect refresh tokens.
func ReadOAuthProvider(path string) (oauthprovider.Spec, error) {
	f, err := os.Open(path)
	if err != nil {
		return oauthprovider.Spec{}, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return oauthprovider.Spec{}, err
	}
	if len(raw) > 64<<10 {
		return oauthprovider.Spec{}, fmt.Errorf("provider file exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var p oauthprovider.Spec
	if err := decoder.Decode(&p); err != nil {
		return p, fmt.Errorf("invalid provider JSON: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return p, fmt.Errorf("provider file must contain exactly one JSON object")
	}
	return oauthprovider.Normalize(p)
}

// NormalizeOAuthProviders is used both on initial launch and persisted resume.
func NormalizeOAuthProviders(cfg *RunConfig) error {
	if len(cfg.OAuthProviders) > oauthprovider.MaxProviders {
		return fmt.Errorf("too many OAuth providers (max %d)", oauthprovider.MaxProviders)
	}
	if len(cfg.OAuthProviders) > 0 && !cfg.OAuthCustodyEnabled() {
		return fmt.Errorf("-oauth-provider requires -oauth-custody")
	}
	seen := map[string]bool{}
	for i, p := range cfg.OAuthProviders {
		normalized, err := oauthprovider.Normalize(p)
		if err != nil {
			return err
		}
		if seen[p.Provider] {
			return fmt.Errorf("duplicate OAuth provider %q", p.Provider)
		}
		seen[p.Provider] = true
		cfg.OAuthProviders[i] = normalized
	}
	return nil
}
