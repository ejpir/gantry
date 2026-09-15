package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/oauthprovider"
)

const customOAuthJSON = `{"name":"company-mcp","authorize_url":"https://auth.example/authorize","token_url":"https://auth.example/token","client_id":"public-client","redirect_uri":"http://127.0.0.1:53693/callback","scope":"mcp offline_access","resource":"https://mcp.example/mcp","credential_hosts":["git.example"]}`

func TestOAuthProviderFileValidation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "provider.json")
	for name, data := range map[string]string{
		"valid":      customOAuthJSON,
		"unknown":    strings.TrimSuffix(customOAuthJSON, "}") + `,"client_secret":"not-supported"}`,
		"trailing":   customOAuthJSON + ` {}`,
		"oversized":  customOAuthJSON + strings.Repeat(" ", 64<<10),
		"guest file": strings.TrimSuffix(customOAuthJSON, "}") + `,"GuestAuthFile":"/tmp/token"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(file, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			p, err := ReadOAuthProvider(file)
			if name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if p.Grant != oauthprovider.AuthorizationCode || p.ExchangeEncoding != oauthprovider.Form {
					t.Fatal("defaults not resolved")
				}
			} else if err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestOAuthProviderConfigRoundTripAndSnapshot(t *testing.T) {
	var p oauthprovider.Spec
	if err := json.Unmarshal([]byte(customOAuthJSON), &p); err != nil {
		t.Fatal(err)
	}
	enabled := true
	cfg := RunConfig{MemMB: 512, VCPUs: 1, OAuthCustody: &enabled, OAuthProviders: []oauthprovider.Spec{p}}
	if err := NormalizeOAuthProviders(&cfg); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadConfigStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	if snapshot.OAuthProviders[0].Provider != "company-mcp" || snapshot.OAuthProviders[0].Resource != p.Resource || snapshot.OAuthProviders[0].RedirectURI != p.RedirectURI || snapshot.OAuthProviders[0].Scope != p.Scope {
		t.Fatal("registration not persisted")
	}
	snapshot.OAuthProviders[0].CredentialHosts[0] = "evil.example"
	if store.Snapshot().OAuthProviders[0].CredentialHosts[0] != "git.example" {
		t.Fatal("snapshot aliased provider bindings")
	}
	cfg.OAuthProviders = append(cfg.OAuthProviders, p)
	if err := NormalizeOAuthProviders(&cfg); err == nil {
		t.Fatal("duplicate provider accepted")
	}
	cfg.OAuthProviders = cfg.OAuthProviders[:1]
	cfg.OAuthCustody = nil
	if err := NormalizeOAuthProviders(&cfg); err == nil {
		t.Fatal("provider enabled without custody")
	}
}
