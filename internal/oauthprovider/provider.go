// Package oauthprovider describes host-authorized OAuth clients independently
// of token custody and delivery. Configurations contain public metadata only.
package oauthprovider

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"maps"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/ejpir/gantry/internal/secret"
)

const (
	AuthorizationCode = "authorization_code"
	DeviceCode        = "device_code"
	Form              = "form"
	JSON              = "json"
	MaxProviders      = 32
)

// Spec is an immutable, host-owned client registration. Custom providers keep
// all tokens on the host; only built-in CLI adapters have a GuestAuthFile.
// CredentialHosts explicitly permits access-token delivery to git helpers;
// MCP delivery is separately authorized by auth=custody:NAME on a remote.
type Spec struct {
	Provider               string   `json:"name"`
	Grant                  string   `json:"grant,omitempty"`
	AuthorizeURL           string   `json:"authorize_url,omitempty"`
	DeviceAuthorizationURL string   `json:"device_authorization_url,omitempty"`
	TokenURL               string   `json:"token_url"`
	ClientID               string   `json:"client_id"`
	RedirectURI            string   `json:"redirect_uri,omitempty"`
	Scope                  string   `json:"scope,omitempty"`
	Resource               string   `json:"resource,omitempty"`
	ExchangeEncoding       string   `json:"exchange_encoding,omitempty"`
	RefreshEncoding        string   `json:"refresh_encoding,omitempty"`
	CredentialHosts        []string `json:"credential_hosts,omitempty"`

	GuestAuthFile string            `json:"-"`
	ExtraParams   map[string]string `json:"-"`
}

// Builtin returns a fresh copy so callers cannot mutate shared registrations.
// Endpoint/client overrides are host-side development hooks, never guest input.
func Builtin(name string) (Spec, bool) {
	var p Spec
	switch strings.ToLower(name) {
	case "claude":
		p = Spec{
			Provider: "claude", Grant: AuthorizationCode,
			AuthorizeURL:     "https://claude.ai/oauth/authorize",
			TokenURL:         "https://console.anthropic.com/v1/oauth/token",
			ClientID:         "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
			RedirectURI:      "http://127.0.0.1:0/callback",
			Scope:            "user:profile user:inference",
			ExchangeEncoding: JSON, RefreshEncoding: JSON,
			GuestAuthFile: "$HOME/.claude/.credentials.json",
		}
	case "codex":
		p = Spec{
			Provider: "codex", Grant: AuthorizationCode,
			AuthorizeURL:     "https://auth.openai.com/oauth/authorize",
			TokenURL:         "https://auth.openai.com/oauth/token",
			ClientID:         "app_EMoamEEZ73f0CkXaXp7hrann",
			RedirectURI:      "http://localhost:1455/auth/callback",
			Scope:            "openid profile email offline_access api.connectors.read api.connectors.invoke",
			ExchangeEncoding: Form, RefreshEncoding: JSON,
			GuestAuthFile: "$HOME/.codex/auth.json",
			ExtraParams: map[string]string{
				"id_token_add_organizations": "true",
				"codex_cli_simplified_flow":  "true",
				"originator":                 "codex_cli_rs",
			},
		}
	case "github":
		p = Spec{
			Provider: "github", Grant: DeviceCode,
			DeviceAuthorizationURL: "https://github.com/login/device/code",
			TokenURL:               "https://github.com/login/oauth/access_token",
			ClientID:               "Iv1.b507a08c87ecfe98", // GitHub CLI's public device-flow client
			Scope:                  "repo read:org gist",
			ExchangeEncoding:       Form, RefreshEncoding: Form,
			CredentialHosts: []string{"github.com"},
		}
	default:
		return Spec{}, false
	}
	for key, target := range map[string]*string{
		"TOKEN_URL": &p.TokenURL, "AUTHORIZE_URL": &p.AuthorizeURL,
		"DEVICE_URL": &p.DeviceAuthorizationURL, "CLIENT_ID": &p.ClientID,
	} {
		if value := os.Getenv("GANTRY_OAUTH_" + key + "_" + strings.ToUpper(p.Provider)); value != "" {
			*target = value
		}
	}
	return p, true
}

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// Normalize validates a custom registration and fills protocol defaults.
func Normalize(p Spec) (Spec, error) {
	if !namePattern.MatchString(p.Provider) {
		return Spec{}, fmt.Errorf("OAuth provider name must match %s", namePattern)
	}
	if _, reserved := Builtin(p.Provider); reserved {
		return Spec{}, fmt.Errorf("OAuth provider %q is built in; use a distinct registration name", p.Provider)
	}
	if p.ClientID == "" || len(p.ClientID) > 256 || len(p.Scope) > 2048 {
		return Spec{}, fmt.Errorf("OAuth provider %s needs a client_id (max 256 bytes) and scope <= 2048 bytes", p.Provider)
	}
	if err := ValidateEndpoint(p.TokenURL); err != nil {
		return Spec{}, fmt.Errorf("OAuth provider %s token_url: %w", p.Provider, err)
	}
	if p.Grant == "" {
		p.Grant = AuthorizationCode
	}
	switch p.Grant {
	case AuthorizationCode:
		if err := ValidateEndpoint(p.AuthorizeURL); err != nil {
			return Spec{}, fmt.Errorf("OAuth provider %s authorize_url: %w", p.Provider, err)
		}
		if p.DeviceAuthorizationURL != "" {
			return Spec{}, fmt.Errorf("authorization_code provider cannot have device_authorization_url")
		}
		if p.RedirectURI == "" {
			p.RedirectURI = "http://127.0.0.1:0/callback"
		}
		port, err := RedirectPort(p.RedirectURI, true)
		if err != nil {
			return Spec{}, err
		}
		if port != 0 && port != 1455 && port < 32768 {
			return Spec{}, fmt.Errorf("OAuth callback port must be 0 (dynamic), 1455, or 32768–65535")
		}
	case DeviceCode:
		if err := ValidateEndpoint(p.DeviceAuthorizationURL); err != nil {
			return Spec{}, fmt.Errorf("OAuth provider %s device_authorization_url: %w", p.Provider, err)
		}
		if p.AuthorizeURL != "" || p.RedirectURI != "" {
			return Spec{}, fmt.Errorf("device_code provider cannot have authorize_url or redirect_uri")
		}
	default:
		return Spec{}, fmt.Errorf("OAuth grant must be authorization_code or device_code")
	}
	if p.Resource != "" {
		if err := ValidateEndpoint(p.Resource); err != nil {
			return Spec{}, fmt.Errorf("OAuth resource: %w", err)
		}
	}
	for _, encoding := range []*string{&p.ExchangeEncoding, &p.RefreshEncoding} {
		if *encoding == "" {
			*encoding = Form
		}
		if *encoding != Form && *encoding != JSON {
			return Spec{}, fmt.Errorf("OAuth encoding must be form or json")
		}
	}
	if len(p.CredentialHosts) > 32 {
		return Spec{}, fmt.Errorf("too many OAuth credential_hosts (max 32)")
	}
	p.CredentialHosts = append([]string(nil), p.CredentialHosts...)
	for i, host := range p.CredentialHosts {
		host = strings.ToLower(host)
		if err := secret.ValidateBinding(host); err != nil || strings.HasPrefix(host, "*.") {
			return Spec{}, fmt.Errorf("OAuth credential_hosts must be exact hostnames without ports or wildcards")
		}
		p.CredentialHosts[i] = host
	}
	p.GuestAuthFile, p.ExtraParams = "", nil
	return p, nil
}

// ValidateEndpoint permits HTTPS, with HTTP only on literal IPv4 loopback for
// local development. Endpoints come only from host configuration, never a guest.
func ValidateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u == nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("expected an absolute URL without userinfo or fragment")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || u.Hostname() != "127.0.0.1") {
		return fmt.Errorf("HTTPS is required (HTTP allowed only on 127.0.0.1)")
	}
	return nil
}

// RedirectPort validates callback shape; configured port 0 chooses a dynamic
// port. The bridge also enforces its bounded callback-port allowlist.
func RedirectPort(raw string, dynamic bool) (int, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Opaque != "" ||
		(u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1") {
		return 0, fmt.Errorf("redirect_uri must be an HTTP IPv4 loopback URL without userinfo, query, or fragment")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 0 || port > 65535 || (!dynamic && port == 0) {
		return 0, fmt.Errorf("redirect_uri needs a usable port")
	}
	return port, nil
}

// Fingerprint binds persisted tokens to their issuance context. Reusing a
// registration name with a different endpoint/client/resource needs re-login.
func (p Spec) Fingerprint() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{p.Provider, p.Grant, p.TokenURL, p.AuthorizeURL, p.DeviceAuthorizationURL, p.ClientID, p.Scope, p.Resource}, "\x00")))
	return fmt.Sprintf("%x", sum)
}

func RandomState() (string, error) { return randomURLSafe(32) }

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Authorization creates PKCE/state host-side and preserves an endpoint's query
// while overwriting security-critical OAuth fields with host-generated values.
func (p Spec) Authorization() (authURL, state, verifier, redirect string, err error) {
	state, err = RandomState()
	if err != nil {
		return
	}
	verifier, err = randomURLSafe(32)
	if err != nil {
		return
	}
	redirect = p.RedirectURI
	var port int
	port, err = RedirectPort(redirect, true)
	if err != nil {
		return
	}
	if port == 0 {
		var random [2]byte
		if _, err = rand.Read(random[:]); err != nil {
			return
		}
		port = 49152 + int(binary.LittleEndian.Uint16(random[:]))%16384
		u, _ := url.Parse(redirect)
		u.Host = u.Hostname() + ":" + strconv.Itoa(port)
		redirect = u.String()
	}
	u, parseErr := url.Parse(p.AuthorizeURL)
	if parseErr != nil {
		err = fmt.Errorf("invalid authorize URL")
		return
	}
	q := u.Query()
	for k, v := range p.ExtraParams {
		q.Set(k, v)
	}
	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", redirect)
	if p.Scope != "" {
		q.Set("scope", p.Scope)
	} else {
		q.Del("scope")
	}
	q.Set("state", state)
	sum := sha256.Sum256([]byte(verifier))
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	if p.Resource != "" {
		q.Set("resource", p.Resource)
	} else {
		q.Del("resource")
	}
	u.RawQuery = q.Encode()
	authURL = u.String()
	return
}

// Lookup resolves a configured name before falling back to built-in adapters.
func Lookup(custom []Spec, name string) (Spec, bool) {
	name = strings.ToLower(name)
	for _, p := range custom {
		if p.Provider == name {
			return p, true
		}
	}
	return Builtin(name)
}

func Clone(specs []Spec) []Spec {
	out := append([]Spec(nil), specs...)
	for i := range out {
		out[i].CredentialHosts = append([]string(nil), out[i].CredentialHosts...)
		out[i].ExtraParams = maps.Clone(out[i].ExtraParams)
	}
	return out
}
