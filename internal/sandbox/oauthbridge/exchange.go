package oauthbridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

type tokenRequestEncoding uint8

const (
	tokenRequestJSON tokenRequestEncoding = iota
	tokenRequestForm
)

// CustodySpec describes a provider the daemon can hold tokens for. Token
// endpoint contracts differ by provider and, for Codex, by grant: the initial
// authorization-code exchange is form-encoded while refreshes are JSON.
type CustodySpec struct {
	Provider         string
	TokenURL         string
	GuestAuthFile    string
	exchangeEncoding tokenRequestEncoding
	refreshEncoding  tokenRequestEncoding
}

// custodySpecs lists providers with custody support. Unknown providers
// are refused loudly at login: custody must never silently degrade to
// guest-held tokens.
var custodySpecs = map[string]CustodySpec{
	"claude": {
		Provider:         "claude",
		TokenURL:         "https://console.anthropic.com/v1/oauth/token",
		GuestAuthFile:    "$HOME/.claude/.credentials.json",
		exchangeEncoding: tokenRequestJSON,
		refreshEncoding:  tokenRequestJSON,
	},
	"codex": {
		Provider:         "codex",
		TokenURL:         "https://auth.openai.com/oauth/token",
		GuestAuthFile:    "$HOME/.codex/auth.json",
		exchangeEncoding: tokenRequestForm,
		refreshEncoding:  tokenRequestJSON,
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
	IDToken      string `json:"id_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in"` // seconds; Codex uses JWT exp instead
	AccountID    string `json:"account_id,omitempty"`
}

// ExpiryAt returns the access-token expiry. Providers that omit expires_in
// (notably Codex) encode exp in their JWTs.
func (t TokenResponse) ExpiryAt(now time.Time) time.Time {
	if t.ExpiresIn > 0 {
		return now.Add(time.Duration(t.ExpiresIn) * time.Second)
	}
	for _, raw := range []string{t.AccessToken, t.IDToken} {
		claims, err := decodeJWTClaims(raw)
		if err != nil {
			continue
		}
		if exp, ok := claims["exp"].(float64); ok && exp > 0 {
			return time.Unix(int64(exp), 0)
		}
	}
	return time.Time{}
}

const tokenHTTPTimeout = 30 * time.Second

// TokenEndpointError reports only the status. Token endpoint response bodies
// may contain sensitive material and are deliberately never retained.
type TokenEndpointError struct {
	StatusCode int
	Status     string
}

func (e *TokenEndpointError) Error() string { return "token endpoint returned " + e.Status }

// IsPermanentTokenError reports OAuth statuses for which retrying the same
// refresh token cannot help.
func IsPermanentTokenError(err error) bool {
	var endpointErr *TokenEndpointError
	return errors.As(err, &endpointErr) && (endpointErr.StatusCode == http.StatusBadRequest || endpointErr.StatusCode == http.StatusUnauthorized)
}

// postToken posts one provider-specific grant and decodes the bounded token
// response. Failures include the status code but never response bodies.
func postToken(ctx context.Context, spec CustodySpec, grant map[string]string, encoding tokenRequestEncoding, requireIDToken bool) (TokenResponse, error) {
	var (
		body        io.Reader
		contentType string
	)
	switch encoding {
	case tokenRequestForm:
		values := make(url.Values, len(grant))
		for key, value := range grant {
			values.Set(key, value)
		}
		body = strings.NewReader(values.Encode())
		contentType = "application/x-www-form-urlencoded"
	default:
		raw, err := json.Marshal(grant)
		if err != nil {
			return TokenResponse{}, err
		}
		body = bytes.NewReader(raw)
		contentType = "application/json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, spec.TokenURL, body)
	if err != nil {
		return TokenResponse{}, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{
		Timeout: tokenHTTPTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("token endpoint redirect refused")
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return TokenResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return TokenResponse{}, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return TokenResponse{}, &TokenEndpointError{StatusCode: resp.StatusCode, Status: resp.Status}
	}
	var tok TokenResponse
	if err := json.Unmarshal(raw, &tok); err != nil {
		return TokenResponse{}, fmt.Errorf("decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return TokenResponse{}, fmt.Errorf("token response carried no access_token")
	}
	if strings.EqualFold(spec.Provider, "codex") {
		if tok.IDToken == "" {
			if requireIDToken {
				return TokenResponse{}, fmt.Errorf("codex token response carried no id_token")
			}
			return tok, nil
		}
		claims, err := decodeJWTClaims(tok.IDToken)
		if err != nil {
			return TokenResponse{}, fmt.Errorf("codex token response carried an invalid id_token: %w", err)
		}
		tok.AccountID = codexAccountID(claims)
	}
	return tok, nil
}

func decodeJWTClaims(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[1] == "" {
		return nil, fmt.Errorf("invalid JWT shape")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func codexAccountID(claims map[string]any) string {
	if account, _ := claims["chatgpt_account_id"].(string); account != "" {
		return account
	}
	auth, _ := claims["https://api.openai.com/auth"].(map[string]any)
	account, _ := auth["chatgpt_account_id"].(string)
	return account
}

// ExchangeCode exchanges an authorization code host-side. The verifier
// is the PKCE verifier the guest helper generated and handed to the
// daemon over the trusted broker channel — it never traverses the
// network from the host except to the provider's token endpoint.
func ExchangeCode(ctx context.Context, spec CustodySpec, code, verifier, clientID, redirectURI string) (TokenResponse, error) {
	return postToken(ctx, spec, map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  redirectURI,
		"client_id":     clientID,
		"code_verifier": verifier,
	}, spec.exchangeEncoding, strings.EqualFold(spec.Provider, "codex"))
}

// RefreshTokens exchanges a refresh token for a fresh access token. A
// rotated refresh token in the response replaces the stored one (sbx's
// re-capture semantics).
func RefreshTokens(ctx context.Context, spec CustodySpec, refreshToken, clientID string) (TokenResponse, error) {
	return postToken(ctx, spec, map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     clientID,
	}, spec.refreshEncoding, false)
}

// SentinelRefresh is the marker written into the guest auth file in place
// of the real refresh token. A CLI that tries to refresh with it fails
// loudly at the provider — the refresh material lives on the host and the
// daemon pushes fresh access tokens instead.
const SentinelRefresh = "gantry-custody-refresh-held-on-host"

// RenderGuestAuthFile renders the provider's guest auth file with the
// current ACCESS token and the sentinel refresh token. Claude stores expiry
// in epoch milliseconds; Codex derives it from the access-token JWT.
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
		if tok.IDToken == "" {
			return nil, fmt.Errorf("codex auth file needs an id_token")
		}
		var accountID any
		if tok.AccountID != "" {
			accountID = tok.AccountID
		}
		return json.MarshalIndent(map[string]any{
			"auth_mode":      "chatgpt",
			"OPENAI_API_KEY": nil,
			"tokens": map[string]any{
				"id_token":      tok.IDToken,
				"access_token":  tok.AccessToken,
				"refresh_token": SentinelRefresh,
				"account_id":    accountID,
			},
			"last_refresh": time.Now().UTC().Format(time.RFC3339Nano),
		}, "", "  ")
	}
	return nil, fmt.Errorf("no guest auth file renderer for provider %q", provider)
}
