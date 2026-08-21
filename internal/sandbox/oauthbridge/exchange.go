package oauthbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Custody-mode host-side token endpoint client (workstream 3). The
// transparent bridge needs no provider knowledge; custody needs exactly
// one: where to POST the code exchange and refresh. client_id and
// redirect_uri are taken from the authorize URL the guest advertised
// (they are public, loopback-bound values), so the registry carries only
// the token endpoint and guest auth-file shape per provider.
//
// GANTRY_OAUTH_TOKEN_URL_<PROVIDER> (uppercased) overrides the endpoint —
// used by tests with a mock authorization server, and an escape hatch if
// a provider moves its endpoint.

// CustodySpec describes a provider the daemon can hold tokens for.
type CustodySpec struct {
	// TokenURL is the OAuth token endpoint (JSON POST).
	TokenURL string
	// GuestAuthFile is the CLI's auth file path inside the guest.
	GuestAuthFile string
}

// custodySpecs lists providers with custody support. Unknown providers
// are refused loudly at login: custody must never silently degrade to
// guest-held tokens.
var custodySpecs = map[string]CustodySpec{
	"claude": {
		TokenURL:      "https://console.anthropic.com/v1/oauth/token",
		GuestAuthFile: "$HOME/.claude/.credentials.json",
	},
	"codex": {
		TokenURL:      "https://auth.openai.com/oauth/token",
		GuestAuthFile: "$HOME/.codex/auth.json",
	},
}

// CustodySpecFor resolves a provider's custody spec, honouring the
// endpoint override.
func CustodySpecFor(provider string) (CustodySpec, bool) {
	spec, ok := custodySpecs[strings.ToLower(provider)]
	if !ok {
		return CustodySpec{}, false
	}
	if override := os.Getenv("GANTRY_OAUTH_TOKEN_URL_" + strings.ToUpper(provider)); override != "" {
		spec.TokenURL = override
	}
	return spec, true
}

// TokenResponse is the subset of a token endpoint response gantry uses.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"` // seconds
}

const tokenHTTPTimeout = 30 * time.Second

// postToken POSTs a JSON grant to the token endpoint and decodes the
// token response. Failures include the status code but never response
// bodies, which can carry sensitive detail.
func postToken(ctx context.Context, tokenURL string, grant map[string]string) (TokenResponse, error) {
	body, err := json.Marshal(grant)
	if err != nil {
		return TokenResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(body))
	if err != nil {
		return TokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: tokenHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return TokenResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return TokenResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return TokenResponse{}, fmt.Errorf("token endpoint returned %s", resp.Status)
	}
	var tok TokenResponse
	if err := json.Unmarshal(raw, &tok); err != nil {
		return TokenResponse{}, fmt.Errorf("decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return TokenResponse{}, fmt.Errorf("token response carried no access_token")
	}
	return tok, nil
}

// ExchangeCode exchanges an authorization code host-side. The verifier
// is the PKCE verifier the guest helper generated and handed to the
// daemon over the trusted broker channel — it never traverses the
// network from the host except to the provider's token endpoint.
func ExchangeCode(ctx context.Context, spec CustodySpec, code, verifier, clientID, redirectURI string) (TokenResponse, error) {
	return postToken(ctx, spec.TokenURL, map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  redirectURI,
		"client_id":     clientID,
		"code_verifier": verifier,
	})
}

// RefreshTokens exchanges a refresh token for a fresh access token. A
// rotated refresh token in the response replaces the stored one (matching
// the reference implementation's re-capture semantics).
func RefreshTokens(ctx context.Context, spec CustodySpec, refreshToken, clientID string) (TokenResponse, error) {
	return postToken(ctx, spec.TokenURL, map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     clientID,
	})
}

// SentinelRefresh is the marker written into the guest auth file in place
// of the real refresh token. A CLI that tries to refresh with it fails
// loudly at the provider — the refresh material lives on the host and the
// daemon pushes fresh access tokens instead.
const SentinelRefresh = "gantry-custody-refresh-held-on-host"

// RenderGuestAuthFile renders the provider's guest auth file with the
// current ACCESS token and the sentinel refresh token. expiry is epoch
// milliseconds (both providers store ms).
func RenderGuestAuthFile(provider string, tok TokenResponse, expiry time.Time) ([]byte, error) {
	var expiryMs int64
	if !expiry.IsZero() {
		expiryMs = expiry.UnixMilli()
	}
	switch strings.ToLower(provider) {
	case "claude":
		return json.MarshalIndent(map[string]any{
			"claudeAiOauth": map[string]any{
				"accessToken":      tok.AccessToken,
				"refreshToken":     SentinelRefresh,
				"expiresAt":        expiryMs,
				"subscriptionType": "custody",
			},
		}, "", "  ")
	case "codex":
		return json.MarshalIndent(map[string]any{
			"tokens": map[string]any{
				"access_token":  tok.AccessToken,
				"refresh_token": SentinelRefresh,
			},
		}, "", "  ")
	}
	return nil, fmt.Errorf("no guest auth file renderer for provider %q", provider)
}
