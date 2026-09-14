package orgauth_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/orgauth"
	"github.com/ejpir/gantry/internal/orgauth/testidp"
	"github.com/ejpir/gantry/internal/policy"
)

func fixture(t *testing.T) (*testidp.Provider, string) {
	t.Helper()
	idp, err := testidp.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)
	path, err := idp.WriteConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return idp, path
}

func TestOIDCProtocolAndMembership(t *testing.T) {
	idp, path := fixture(t)
	trusted, err := orgauth.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, requested, want string
		groups                any
	}{
		{name: "array", want: "developer"},
		{name: "string", groups: "example-developers", want: "developer"},
		{name: "explicit", requested: "developer", want: "developer"},
		{name: "admin membership", groups: []string{"example-admins"}, want: "admin"},
		{name: "multi choose", groups: []string{"example-developers", "example-admins"}, requested: "developer", want: "developer"},
		{name: "no membership", groups: []string{}},
		{name: "unmapped", groups: []string{"other-organization"}},
		{name: "malformed", groups: map[string]bool{"example-developers": true}},
		{name: "ambiguous", groups: []string{"example-developers", "example-admins"}},
		{name: "cannot select admin", requested: "admin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp.Set(testidp.Scenario{Groups: tc.groups})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			s, err := orgauth.Login(ctx, trusted, tc.requested, idp.Visit)
			if tc.want == "" {
				if err == nil || s != nil {
					t.Fatal("unauthorized membership accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.Profile != tc.want || s.Subject != "synthetic-user" || s.Issuer != idp.Server.URL || s.Organization != testidp.Organization || s.Validate() != nil {
				t.Fatalf("unexpected login receipt: %+v", s)
			}
			engine, err := policy.New(s.Policy, nil)
			if err != nil {
				t.Fatal(err)
			}
			d := engine.Evaluate(ctx, policy.MCPCall, policy.Resource{Server: "fs", Tool: "write_file"})
			if (d.Effect == "allow") != (tc.want == "admin") {
				t.Fatalf("wrong profile authority: %+v", d)
			}
		})
	}
	for _, endpoint := range []string{"/.well-known/openid-configuration", "/authorize", "/token", "/keys"} {
		if idp.Count(endpoint) == 0 {
			t.Errorf("real OIDC endpoint was never exercised: %s", endpoint)
		}
	}
}

func TestOIDCRejectsInvalidResponsesWithoutEchoingSecrets(t *testing.T) {
	idp, path := fixture(t)
	trusted, err := orgauth.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{
		"issuer", "audience", "nonce", "signature", "expired", "future-iat", "future-nbf", "azp", "multi-aud",
		"no-subject", "no-groups", "at-hash", "no-id-token", "pkce", "denied", "discovery-issuer", "http-endpoint", "oversized-discovery", "token-redirect",
	} {
		t.Run(fault, func(t *testing.T) {
			idp.Set(testidp.Scenario{Fault: fault})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if s, err := orgauth.Login(ctx, trusted, "", idp.Visit); err == nil || s != nil {
				t.Fatal("invalid OIDC response accepted")
			} else {
				for _, secret := range append(idp.Secrets(), "UPSTREAM-ERROR-CANARY") {
					if strings.Contains(err.Error(), secret) {
						t.Fatal("upstream credential or error body leaked")
					}
				}
			}
		})
	}
	if idp.Count("/leak") != 0 {
		t.Fatal("token exchange followed a redirect")
	}
}

func TestOIDCPinsFilesBeforeBrowserRoundTrip(t *testing.T) {
	idp, path := fixture(t)
	trusted, err := orgauth.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := orgauth.Login(ctx, trusted, "", func(url string) error {
		for _, file := range []string{path, filepath.Join(filepath.Dir(path), "bundle.tar.gz"), filepath.Join(filepath.Dir(path), "policy-public.pem"), filepath.Join(filepath.Dir(path), "ca.pem")} {
			if err := os.WriteFile(file, []byte("replaced during login"), 0o600); err != nil {
				return err
			}
		}
		return idp.Visit(url)
	})
	if err != nil || s.Validate() != nil {
		t.Fatalf("pinned login failed: %v", err)
	}
}

func TestOIDCConfigurationRejectsUntrustedOrUnsupportedInputs(t *testing.T) {
	idp, path := fixture(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*orgauth.Config){
		"http":         func(c *orgauth.Config) { c.Issuer = "http://127.0.0.1:1234" },
		"issuer query": func(c *orgauth.Config) { c.Issuer += "?token=private" },
		"issuer user":  func(c *orgauth.Config) { c.Issuer = "https://user:secret@example.com" },
		"wrong org":    func(c *orgauth.Config) { c.Organization = "other" },
		"no client":    func(c *orgauth.Config) { c.ClientID = "" },
		"no groups":    func(c *orgauth.Config) { c.GroupProfiles = nil },
		"bad profile":  func(c *orgauth.Config) { c.GroupProfiles["x"] = "not-in-bundle" },
		"refresh":      func(c *orgauth.Config) { c.Scopes = []string{"offline_access"} },
		"no bundle":    func(c *orgauth.Config) { c.Bundle = "" },
	} {
		t.Run(name, func(t *testing.T) {
			var c orgauth.Config
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatal(err)
			}
			change(&c)
			modified, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, modified, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := orgauth.LoadConfig(path); err == nil {
				t.Fatal("invalid organization config accepted")
			}
		})
	}
	var c orgauth.Config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.CAFile = "" // Fixture certificate must NOT be accepted by the system trust store.
	modified, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, modified, 0o600); err != nil {
		t.Fatal(err)
	}
	trusted, err := orgauth.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := orgauth.Login(ctx, trusted, "", idp.Visit); err == nil {
		t.Fatal("untrusted test CA accepted")
	}
}

func TestOIDCCancellation(t *testing.T) {
	idp, path := fixture(t)
	trusted, err := orgauth.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, err = orgauth.Login(ctx, trusted, "", func(string) error { cancel(); return nil })
	if err == nil || idp.Count("/token") != 0 {
		t.Fatal("canceled login exchanged a code")
	}
}
