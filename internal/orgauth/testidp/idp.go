// Package testidp implements loopback-only, disposable OAuth 2.0 and OIDC
// protocol fixtures. They automatically authenticate a synthetic user. They
// are NOT production IdPs and are imported only by tests and E2E drivers.
package testidp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

const ClientID = "gantry-test-cli"

// Scenario changes only the test provider's protocol behavior. Production
// Gantry has no fixture flag, alternate verifier, or authentication bypass.
type Scenario struct {
	Fault           string
	Groups          any    // nil means the default developer group; empty slice means no membership
	Resource, Scope string // optional required catalog audience and permission
}

type grant struct {
	client, redirect, nonce, challenge string
	scenario                           Scenario
	resource, scope                    string
}

type Provider struct {
	Server *httptest.Server
	CA     []byte

	mu           sync.Mutex
	key          *rsa.PrivateKey
	grants       map[string]grant
	scenario     Scenario
	requests     map[string]int
	secrets      []string
	accessGrants map[string]grant
}

func New() (*Provider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	cert, ca, err := certificate()
	if err != nil {
		return nil, err
	}
	p := &Provider{key: key, CA: ca, grants: make(map[string]grant), requests: make(map[string]int), accessGrants: make(map[string]grant)}
	p.Server = httptest.NewUnstartedServer(http.HandlerFunc(p.serve))
	p.Server.Config.ErrorLog = log.New(io.Discard, "", 0)
	p.Server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	p.Server.StartTLS()
	return p, nil
}

func certificate() (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Gantry disposable OIDC test IdP"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (p *Provider) Close() { p.Server.Close() }

func (p *Provider) Set(s Scenario) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.scenario = s
}

func (p *Provider) Count(path string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests[path]
}

func (p *Provider) Secrets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.secrets...)
}

// ValidAccessToken is the test catalog's audience/scope check. ID and refresh
// tokens (also present in Secrets for leak assertions) cannot satisfy it.
func (p *Provider) ValidAccessToken(token, resource, scope string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	g, ok := p.accessGrants[token]
	return ok && resource != "" && scope != "" && g.resource == resource && strings.Contains(" "+g.scope+" ", " "+scope+" ")
}

func (p *Provider) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests[r.URL.Path]++
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		issuer := p.Server.URL
		if p.scenario.Fault == "discovery-issuer" {
			issuer += "/wrong"
		}
		tokenEndpoint := p.Server.URL + "/token"
		if p.scenario.Fault == "http-endpoint" {
			tokenEndpoint = strings.Replace(tokenEndpoint, "https:", "http:", 1)
		}
		if p.scenario.Fault == "oversized-discovery" {
			_, _ = io.WriteString(w, strings.Repeat("x", (1<<20)+1))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer, "authorization_endpoint": p.Server.URL + "/authorize", "token_endpoint": tokenEndpoint,
			"jwks_uri": p.Server.URL + "/keys", "response_types_supported": []string{"code"},
			"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported": []string{"S256"},
		})
	case "/keys":
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}}})
	case "/authorize":
		p.authorize(w, r)
	case "/token":
		p.exchange(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || redirect.Scheme != "http" || redirect.Hostname() != "127.0.0.1" || redirect.Port() == "" || redirect.Path != "/oidc/callback" || redirect.User != nil || redirect.RawQuery != "" || redirect.Fragment != "" ||
		q.Get("client_id") != ClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || q.Get("state") == "" || q.Get("nonce") == "" || !strings.Contains(" "+q.Get("scope")+" ", " openid ") {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	if p.scenario.Resource != "" && (q.Get("resource") != p.scenario.Resource || !strings.Contains(" "+q.Get("scope")+" ", " "+p.scenario.Scope+" ")) {
		http.Error(w, "missing resource or scope", http.StatusBadRequest)
		return
	}
	code := oauth2.GenerateVerifier()
	p.grants[code] = grant{client: q.Get("client_id"), redirect: redirect.String(), nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), scenario: p.scenario, resource: q.Get("resource"), scope: q.Get("scope")}
	p.secrets = append(p.secrets, code)
	response := url.Values{"state": {q.Get("state")}, "code": {code}, "iss": {p.Server.URL}}
	switch p.scenario.Fault {
	case "denied":
		response.Del("code")
		response.Set("error", "access_denied")
		response.Set("error_description", "UPSTREAM-ERROR-CANARY")
	case "callback-state":
		response.Set("state", "wrong-state")
	case "callback-issuer":
		response.Set("iss", p.Server.URL+"/wrong")
	case "duplicate-state":
		response.Add("state", "second-state")
	}
	redirect.RawQuery = response.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (p *Provider) exchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if r.ParseForm() != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	g, ok := p.grants[r.Form.Get("code")]
	delete(p.grants, r.Form.Get("code")) // codes are single-use, including failures
	hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if !ok || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("client_id") != g.client || r.Form.Get("redirect_uri") != g.redirect || r.Form.Get("client_secret") != "" || base64.RawURLEncoding.EncodeToString(hash[:]) != g.challenge || g.scenario.Fault == "pkce" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "UPSTREAM-ERROR-CANARY"})
		return
	}
	if r.Form.Get("resource") != g.resource {
		http.Error(w, "resource binding mismatch", http.StatusBadRequest)
		return
	}
	if g.scenario.Fault == "token-redirect" {
		http.Redirect(w, r, p.Server.URL+"/leak", http.StatusTemporaryRedirect)
		return
	}
	access, refresh := oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	p.accessGrants[access] = g
	p.secrets = append(p.secrets, access, refresh, r.Form.Get("code_verifier"))
	groups := g.scenario.Groups
	if groups == nil {
		groups = []string{"example-developers"}
	}
	claims := map[string]any{
		"iss": p.Server.URL, "aud": ClientID, "sub": "synthetic-user", "iat": time.Now().Unix(),
		"exp": time.Now().Add(10 * time.Minute).Unix(), "nonce": g.nonce, "groups": groups,
	}
	switch g.scenario.Fault {
	case "issuer":
		claims["iss"] = p.Server.URL + "/wrong"
	case "audience":
		claims["aud"] = "another-client"
	case "nonce":
		claims["nonce"] = "wrong-nonce"
	case "expired":
		claims["exp"] = time.Now().Add(-time.Minute).Unix()
	case "short-lived":
		claims["exp"] = time.Now().Add(5 * time.Second).Unix()
	case "future-iat":
		claims["iat"] = time.Now().Add(time.Hour).Unix()
	case "future-nbf":
		claims["nbf"] = time.Now().Add(time.Hour).Unix()
	case "azp":
		claims["azp"] = "another-client"
	case "multi-aud":
		claims["aud"] = []string{ClientID, "another-client"}
	case "no-subject":
		delete(claims, "sub")
	case "no-groups":
		delete(claims, "groups")
		claims["email"], claims["email_verified"] = "user@example.com", true
	case "at-hash":
		claims["at_hash"] = "incorrect"
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, "fixture claims failed", http.StatusInternalServerError)
		return
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"))
	if err != nil {
		http.Error(w, "fixture signer failed", http.StatusInternalServerError)
		return
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		http.Error(w, "fixture signature failed", http.StatusInternalServerError)
		return
	}
	raw, err := signed.CompactSerialize()
	if err != nil {
		http.Error(w, "fixture serialization failed", http.StatusInternalServerError)
		return
	}
	if g.scenario.Fault == "signature" {
		parts := strings.Split(raw, ".")
		signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
		signature[0] ^= 1
		raw = parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	p.secrets = append(p.secrets, raw)
	result := map[string]any{"access_token": access, "refresh_token": refresh, "token_type": "Bearer", "expires_in": 600, "id_token": raw}
	if g.scenario.Fault == "no-id-token" {
		delete(result, "id_token")
	}
	_ = json.NewEncoder(w).Encode(result)
}

// Visit emulates browser navigation, not Gantry's verification or exchange.
// It trusts only this fixture's ephemeral CA and only visits its authorization
// endpoint and the native app's loopback callback.
func (p *Provider) Visit(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme+"://"+u.Host != p.Server.URL || u.Path != "/authorize" {
		return fmt.Errorf("unexpected authorization URL")
	}
	client := *p.Server.Client()
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) != 1 || r.URL.Scheme != "http" || r.URL.Hostname() != "127.0.0.1" || r.URL.Path != "/oidc/callback" || r.URL.User != nil {
			return fmt.Errorf("unexpected browser redirect")
		}
		return nil
	}
	response, err := client.Get(raw)
	if err != nil {
		return fmt.Errorf("test browser navigation failed")
	}
	defer func() { _ = response.Body.Close() }()
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return err
}
