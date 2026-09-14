package testidp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/ejpir/gantry/internal/orgauth"
	"github.com/ejpir/gantry/internal/policy"
)

const Organization = "example-org"

// WriteConfig creates a signed policy with a key independent of the IdP's key.
// No private key is written. dir must be a caller-owned private directory.
func (p *Provider) WriteConfig(dir string) (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	signed, err := policy.SignDocument(policy.Document{
		Version: 1, Organization: Organization, Revision: "oidc-e2e-1", ExpiresAt: time.Now().Add(time.Hour).UTC(),
		Profiles: map[string]policy.Profile{
			"developer": {Rules: []policy.Rule{{ID: "read", Effect: "allow", Action: policy.MCPCall, Server: "fs", Tool: "read_file"}}},
			"admin":     {Rules: []policy.Rule{{ID: "all-tools", Effect: "allow", Action: policy.MCPCall, Server: "fs", Tool: "*"}}},
		},
	}, key)
	if err != nil {
		return "", err
	}
	cfg := orgauth.Config{
		Version: 1, Organization: Organization, Issuer: p.Server.URL, ClientID: ClientID,
		Scopes: []string{"groups"}, GroupClaim: "groups",
		GroupProfiles: map[string]string{"example-developers": "developer", "example-admins": "admin"},
		Bundle:        "bundle.tar.gz", PublicKey: "policy-public.pem", CAFile: "ca.pem",
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	for name, data := range map[string][]byte{"organization.json": raw, "bundle.tar.gz": signed.Bundle, "policy-public.pem": signed.PublicKey, "ca.pem": p.CA} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, "organization.json"), nil
}
