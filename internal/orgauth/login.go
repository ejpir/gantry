package orgauth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ejpir/gantry/internal/policy"
	"golang.org/x/oauth2"
)

// Login implements native-app authorization code + S256 PKCE. visit receives
// the authorization URL after the loopback listener is ready. It may launch a
// browser, display the URL, or drive a real test IdP; it cannot supply a token.
func Login(ctx context.Context, trusted *ProviderConfig, requested string, visit func(string) error) (*Session, error) {
	if trusted == nil || visit == nil || requested != "" && !identifier(requested) {
		return nil, fmt.Errorf("invalid organization login options")
	}
	c := trusted.config
	client, closeClient, err := oidcClient(trusted.ca)
	if err != nil {
		return nil, err
	}
	defer closeClient()
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		// Upstream errors can contain response bodies, token claims, or URLs
		// with authorization codes. Only fixed diagnostics cross this boundary.
		return nil, fmt.Errorf("OIDC discovery failed (check issuer, TLS trust and connectivity)")
	}
	var metadata struct {
		JWKS string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, fmt.Errorf("invalid OIDC discovery metadata")
	}
	endpoint := provider.Endpoint()
	for _, raw := range []string{endpoint.AuthURL, endpoint.TokenURL, metadata.JWKS} {
		if _, err := httpsURL(raw); err != nil {
			return nil, fmt.Errorf("OIDC authorization, token and JWKS endpoints must use HTTPS")
		}
	}
	endpoint.AuthStyle = oauth2.AuthStyleInParams // public native client: no client secret, no auth-style probing
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(c.RedirectPort))))
	if err != nil {
		return nil, fmt.Errorf("cannot listen for OIDC callback: %w", err)
	}
	defer func() { _ = listener.Close() }()
	redirect := "http://" + listener.Addr().String() + "/oidc/callback"
	state, nonce, verifier := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	callback := newCallback(redirect, c.Issuer, state)
	server := &http.Server{
		Handler: callback, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: log.New(io.Discard, "", 0),
	}
	defer func() { _ = server.Close() }()
	serveError := make(chan error, 1)
	go func() { serveError <- server.Serve(listener) }()
	scopes := []string{oidc.ScopeOpenID}
	for _, scope := range c.Scopes {
		if !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	authOptions := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)}
	exchangeOptions := []oauth2.AuthCodeOption{oauth2.VerifierOption(verifier)}
	if c.RemoteCatalog != nil {
		if !slices.Contains(scopes, c.RemoteCatalog.Scope) {
			scopes = append(scopes, c.RemoteCatalog.Scope)
		}
		authOptions = append(authOptions, catalogResource(c.RemoteCatalog))
		exchangeOptions = append(exchangeOptions, catalogResource(c.RemoteCatalog))
	}
	oauth := oauth2.Config{ClientID: c.ClientID, Endpoint: endpoint, RedirectURL: redirect, Scopes: scopes}
	if err := visit(oauth.AuthCodeURL(state, authOptions...)); err != nil {
		return nil, fmt.Errorf("could not present OIDC authorization URL")
	}
	var response callbackResponse
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("organization login canceled or timed out")
	case <-serveError:
		return nil, fmt.Errorf("OIDC callback listener stopped")
	case response = <-callback.result:
	}
	if response.denied {
		return nil, fmt.Errorf("identity provider denied organization login")
	}
	tokens, err := oauth.Exchange(ctx, response.code, exchangeOptions...)
	if err != nil {
		return nil, fmt.Errorf("OIDC code exchange failed")
	}
	raw, ok := tokens.Extra("id_token").(string)
	if !ok || len(raw) == 0 || len(raw) > 64<<10 {
		return nil, fmt.Errorf("OIDC response requires a bounded ID token")
	}
	id, err := provider.VerifierContext(ctx, &oidc.Config{
		ClientID:             c.ClientID,
		SupportedSigningAlgs: []string{oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256, oidc.ES384, oidc.ES512, oidc.EdDSA},
	}).Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("OIDC ID token verification failed")
	}
	if id.Issuer != c.Issuer || subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(nonce)) != 1 || !text(id.Subject, 255) || id.IssuedAt.IsZero() || id.IssuedAt.After(time.Now().Add(time.Minute)) || id.IssuedAt.After(id.Expiry) || !time.Now().Before(id.Expiry) {
		return nil, fmt.Errorf("OIDC ID token binding or lifetime is invalid")
	}
	if id.AccessTokenHash != "" {
		if tokens.AccessToken == "" || id.VerifyAccessToken(tokens.AccessToken) != nil {
			return nil, fmt.Errorf("OIDC access-token binding is invalid")
		}
	}
	var claims map[string]json.RawMessage
	if err := id.Claims(&claims); err != nil {
		return nil, fmt.Errorf("invalid OIDC claims")
	}
	var party string
	if raw, present := claims["azp"]; present {
		if json.Unmarshal(raw, &party) != nil || party != c.ClientID {
			return nil, fmt.Errorf("OIDC authorized party does not match client")
		}
	} else if len(id.Audience) > 1 {
		return nil, fmt.Errorf("OIDC token with multiple audiences requires azp")
	}
	profile, err := selectProfile(c, claims[c.GroupClaim], requested)
	if err != nil {
		return nil, err
	}
	snapshot := policy.CloneConfig(trusted.snapshot)
	snapshot.Profile = profile
	engine, err := policy.New(snapshot, nil)
	if err != nil {
		return nil, fmt.Errorf("organization policy is no longer valid")
	}
	expires := id.Expiry
	if engine.ExpiresAt().Before(expires) {
		expires = engine.ExpiresAt()
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("organization login canceled or timed out")
	}
	session := &Session{
		Version: 1, Organization: c.Organization, Issuer: c.Issuer, ClientID: c.ClientID,
		Subject: id.Subject, Profile: profile, ExpiresAt: expires, Policy: snapshot,
	}
	if c.RemoteCatalog != nil {
		catalog, err := fetchCatalog(ctx, trusted, tokens, session)
		if err != nil {
			// Discovery is optional inventory, not identity or authorization.
			// A failed refresh clears suggestions, but not a valid login.
			session.CatalogError = err.Error()
		} else {
			session.Catalog = catalog
		}
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("organization login canceled or timed out")
	}
	return session, nil
}

func selectProfile(c Config, raw json.RawMessage, requested string) (string, error) {
	var groups []string
	if json.Unmarshal(raw, &groups) != nil {
		var group string
		if json.Unmarshal(raw, &group) != nil {
			return "", fmt.Errorf("ID token lacks a supported membership claim")
		}
		groups = []string{group}
	}
	if len(groups) > 256 {
		return "", fmt.Errorf("too many membership values")
	}
	var allowed []string
	for _, group := range groups {
		if !text(group, 256) {
			return "", fmt.Errorf("invalid membership value")
		}
		if profile, ok := c.GroupProfiles[group]; ok && !slices.Contains(allowed, profile) {
			allowed = append(allowed, profile)
		}
	}
	if requested != "" && slices.Contains(allowed, requested) {
		return requested, nil
	}
	if requested == "" && len(allowed) == 1 {
		return allowed[0], nil
	}
	if requested == "" && len(allowed) > 1 {
		return "", fmt.Errorf("multiple authorized profiles; choose one with -profile")
	}
	return "", fmt.Errorf("organization membership does not authorize the requested profile")
}

type callbackResponse struct {
	code   string
	denied bool
}

type loginCallback struct {
	host, issuer, state string
	used                atomic.Bool
	result              chan callbackResponse
}

func newCallback(redirect, issuer, state string) *loginCallback {
	u, _ := url.Parse(redirect)
	return &loginCallback{host: u.Host, issuer: issuer, state: state, result: make(chan callbackResponse, 1)}
}

func (c *loginCallback) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet || r.Host != c.host || r.URL.Path != "/oidc/callback" || len(r.URL.RawQuery) > 8192 {
		http.Error(w, "Invalid callback.", http.StatusBadRequest)
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	hasCode := len(q["code"]) == 1 && q.Get("code") != "" && len(q["error"]) == 0
	hasError := len(q["error"]) == 1 && q.Get("error") != "" && len(q["code"]) == 0
	if err != nil || len(q["state"]) != 1 || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(c.state)) != 1 ||
		len(q["iss"]) > 1 || len(q["iss"]) == 1 && q.Get("iss") != c.issuer ||
		!hasCode && !hasError {
		http.Error(w, "Invalid authorization response.", http.StatusBadRequest)
		return
	}
	if !c.used.CompareAndSwap(false, true) {
		http.Error(w, "Authorization response already received.", http.StatusConflict)
		return
	}
	_, _ = io.WriteString(w, "Authorization response received. Return to Gantry for the verification result.\n")
	c.result <- callbackResponse{code: q.Get("code"), denied: q.Get("error") != ""}
}
