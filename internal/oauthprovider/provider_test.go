package oauthprovider

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func testSpec() Spec {
	return Spec{Provider: "company-mcp", AuthorizeURL: "https://auth.example/authorize", TokenURL: "https://auth.example/token", ClientID: "public-client", Scope: "mcp offline_access", Resource: "https://mcp.example/mcp"}
}

func TestNormalizeAndAuthorization(t *testing.T) {
	p := testSpec()
	p.AuthorizeURL += "?prompt=consent&state=untrusted&client_id=untrusted&code_challenge=untrusted"
	p, err := Normalize(p)
	if err != nil {
		t.Fatal(err)
	}
	if p.ExchangeEncoding != Form || p.RefreshEncoding != Form || p.GuestAuthFile != "" {
		t.Fatal("wrong generic defaults")
	}
	auth, state, verifier, redirect, err := p.Authorization()
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(auth)
	q := u.Query()
	sum := sha256.Sum256([]byte(verifier))
	for k, want := range map[string]string{
		"state": state, "client_id": p.ClientID, "redirect_uri": redirect,
		"scope": p.Scope, "resource": p.Resource, "prompt": "consent",
		"code_challenge_method": "S256", "code_challenge": base64.RawURLEncoding.EncodeToString(sum[:]),
	} {
		if q.Get(k) != want || len(q[k]) != 1 {
			t.Errorf("bad authorize parameter %s", k)
		}
	}
	if len(verifier) < 43 || len(state) < 32 || strings.Contains(auth, verifier) {
		t.Fatal("PKCE material not kept private")
	}
	port, err := RedirectPort(redirect, false)
	if err != nil || port < 49152 || port > 65535 {
		t.Fatal("invalid dynamic callback port")
	}
}

func TestNormalizeRejectsUnsafeOrUnsupportedRegistrations(t *testing.T) {
	for name, mutate := range map[string]func(*Spec){
		"reserved":                 func(p *Spec) { p.Provider = "codex" },
		"name":                     func(p *Spec) { p.Provider = "../bad" },
		"client":                   func(p *Spec) { p.ClientID = "" },
		"token http":               func(p *Spec) { p.TokenURL = "http://auth.example/token" },
		"userinfo":                 func(p *Spec) { p.TokenURL = "https://u:p@auth.example/token" },
		"fragment":                 func(p *Spec) { p.TokenURL += "#bad" },
		"grant":                    func(p *Spec) { p.Grant = "password" },
		"encoding":                 func(p *Spec) { p.ExchangeEncoding = "xml" },
		"redirect host":            func(p *Spec) { p.RedirectURI = "http://evil.example:50000/callback" },
		"redirect query":           func(p *Spec) { p.RedirectURI = "http://127.0.0.1:50000/callback?x=y" },
		"redirect port":            func(p *Spec) { p.RedirectURI = "http://localhost:99999/callback" },
		"disallowed callback port": func(p *Spec) { p.RedirectURI = "http://localhost:3000/callback" },
		"resource":                 func(p *Spec) { p.Resource = "http://mcp.example/mcp" },
		"wildcard":                 func(p *Spec) { p.CredentialHosts = []string{"*.example.com"} },
		"credential port":          func(p *Spec) { p.CredentialHosts = []string{"example.com:443"} },
		"mixed grants":             func(p *Spec) { p.DeviceAuthorizationURL = "https://auth.example/device" },
	} {
		t.Run(name, func(t *testing.T) {
			p := testSpec()
			mutate(&p)
			if _, err := Normalize(p); err == nil {
				t.Fatal("accepted invalid provider")
			}
		})
	}
}

func TestCodexCustodyPreservesCLIRegistration(t *testing.T) {
	p, _ := Builtin("codex")
	if p.RedirectURI != "http://localhost:1455/auth/callback" {
		t.Fatal("wrong Codex redirect")
	}
	for _, scope := range []string{"openid", "offline_access", "api.connectors.read", "api.connectors.invoke"} {
		if !strings.Contains(p.Scope, scope) {
			t.Errorf("missing Codex scope %s", scope)
		}
	}
	if p.ExtraParams["id_token_add_organizations"] != "true" || p.ExtraParams["codex_cli_simplified_flow"] != "true" || p.ExtraParams["originator"] != "codex_cli_rs" {
		t.Fatal("wrong Codex extra parameters")
	}
	if p.ExchangeEncoding != Form || p.RefreshEncoding != JSON {
		t.Fatal("wrong Codex encodings")
	}
}

func TestRegistrationFingerprintTracksIssuanceContext(t *testing.T) {
	p := testSpec()
	original := p.Fingerprint()
	p.Resource += "/other"
	if p.Fingerprint() == original {
		t.Fatal("resource change retained token context")
	}
	p = testSpec()
	p.TokenURL = "https://another.example/token"
	if p.Fingerprint() == original {
		t.Fatal("endpoint change retained token context")
	}
}
