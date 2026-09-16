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
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/oauthprovider"
)

// CustodySpec is public, host-owned provider metadata. Delivery adapters are
// independent of the standard OAuth grant client below.
type CustodySpec = oauthprovider.Spec

func CustodySpecFor(provider string) (CustodySpec, bool) {
	return oauthprovider.Builtin(provider)
}

// TokenResponse is the subset of a token endpoint response gantry uses.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in"` // seconds; Codex uses JWT exp instead
	AccountID    string `json:"account_id,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
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
	// Code is a recognized OAuth error only, never arbitrary endpoint text.
	Code string
}

func (e *TokenEndpointError) Error() string {
	if e.Code != "" {
		return "token endpoint returned " + e.Status + " (" + e.Code + ")"
	}
	return "token endpoint returned " + e.Status
}

// IsPermanentTokenError reports OAuth statuses for which retrying the same
// refresh token cannot help.
func IsPermanentTokenError(err error) bool {
	var endpointErr *TokenEndpointError
	return errors.As(err, &endpointErr) && (endpointErr.Code == "invalid_grant" || endpointErr.Code == "invalid_client" || endpointErr.Code == "unauthorized_client" || endpointErr.StatusCode == http.StatusUnauthorized || (endpointErr.StatusCode == http.StatusBadRequest && endpointErr.Code == ""))
}

// postGrant posts one provider-specific grant and reads a bounded response.
// Failures include the status and recognized error codes, never body text.
func postGrant(ctx context.Context, endpoint string, grant map[string]string, encoding string) ([]byte, error) {
	var (
		body        io.Reader
		contentType string
	)
	switch encoding {
	case oauthprovider.Form:
		values := make(url.Values, len(grant))
		for key, value := range grant {
			values.Set(key, value)
		}
		body = strings.NewReader(values.Encode())
		contentType = "application/x-www-form-urlencoded"
	default:
		raw, err := json.Marshal(grant)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
		contentType = "application/json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("invalid token endpoint request")
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
		// Transport errors may include endpoint query parameters.
		return nil, fmt.Errorf("token endpoint request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, fmt.Errorf("token endpoint response unreadable or oversized")
	}
	var failure struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &failure)
	if failure.Error != "" || resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		code := ""
		switch failure.Error {
		case "authorization_pending", "slow_down", "access_denied", "expired_token", "invalid_grant", "invalid_client", "unauthorized_client", "invalid_scope", "unsupported_grant_type", "temporarily_unavailable", "server_error":
			code = failure.Error
		}
		return nil, &TokenEndpointError{StatusCode: resp.StatusCode, Status: fmt.Sprintf("HTTP %d", resp.StatusCode), Code: code}
	}
	return raw, nil
}

func postToken(ctx context.Context, spec CustodySpec, grant map[string]string, encoding string, requireIDToken bool) (TokenResponse, error) {
	if spec.Resource != "" {
		grant["resource"] = spec.Resource
	}
	raw, err := postGrant(ctx, spec.TokenURL, grant, encoding)
	if err != nil {
		return TokenResponse{}, err
	}
	var tok TokenResponse
	if err := json.Unmarshal(raw, &tok); err != nil {
		return TokenResponse{}, fmt.Errorf("invalid token response JSON")
	}
	if tok.TokenType != "" && !strings.EqualFold(tok.TokenType, "bearer") {
		return TokenResponse{}, fmt.Errorf("unsupported token_type (expected bearer)")
	}
	if tok.ExpiresIn < 0 || tok.ExpiresIn > int64((1<<63-1)/time.Second) {
		return TokenResponse{}, fmt.Errorf("invalid access-token lifetime")
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
			return TokenResponse{}, fmt.Errorf("codex token response carried an invalid id_token")
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

// ExchangeCode exchanges an authorization code host-side. The PKCE verifier
// never traverses the network except to the configured token endpoint.
func ExchangeCode(ctx context.Context, spec CustodySpec, code, verifier, clientID, redirectURI string) (TokenResponse, error) {
	return postToken(ctx, spec, map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  redirectURI,
		"client_id":     clientID,
		"code_verifier": verifier,
	}, spec.ExchangeEncoding, strings.EqualFold(spec.Provider, "codex"))
}

// RefreshTokens exchanges a refresh token for a fresh access token. A
// rotated refresh token in the response replaces the stored one (matching
// the reference implementation's re-capture semantics).
func RefreshTokens(ctx context.Context, spec CustodySpec, refreshToken, clientID string) (TokenResponse, error) {
	return postToken(ctx, spec, map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     clientID,
	}, spec.RefreshEncoding, false)
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
