package oauthbridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/oauthprovider"
	"github.com/ejpir/gantry/internal/orgauth/testidp"
)

func TestPublicClientAgainstDisposableAuthorizationServer(t *testing.T) {
	provider := testidp.NewOAuth()
	defer provider.Close()
	spec, err := oauthprovider.Normalize(oauthprovider.Spec{
		Provider: "company-mcp", AuthorizeURL: provider.URL() + "/authorize",
		TokenURL: provider.URL() + "/token", ClientID: testidp.OAuthClientID,
		RedirectURI: "http://127.0.0.1:53693/callback", Scope: testidp.OAuthScope,
		Resource: provider.URL() + "/mcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizeURL, state, verifier, redirect, err := spec.Authorization()
	if err != nil {
		t.Fatal(err)
	}
	client := *provider.Server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	callback, err := url.Parse(response.Header.Get("Location"))
	if err != nil || response.StatusCode != http.StatusFound || callback.Query().Get("state") != state || callback.Query().Get("code") == "" {
		t.Fatalf("authorization response: status=%d callback=%v error=%v", response.StatusCode, callback, err)
	}
	tokens, err := ExchangeCode(context.Background(), spec, callback.Query().Get("code"), verifier, spec.ClientID, redirect)
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != testidp.MCPAccessPrefix+"0" || tokens.RefreshToken != testidp.MCPRefreshPrefix+"0" {
		t.Fatal("authorization-code exchange returned the wrong tokens")
	}
	rotated, err := RefreshTokens(context.Background(), spec, tokens.RefreshToken, spec.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.AccessToken != testidp.MCPAccessPrefix+"1" || rotated.RefreshToken != testidp.MCPRefreshPrefix+"1" {
		t.Fatal("refresh exchange did not rotate both tokens")
	}
	observations := provider.Observations()
	if observations.Exchanges != 1 || observations.Refreshes != 1 || len(observations.Errors) != 0 {
		t.Fatalf("authorization server observations: %+v", observations)
	}
}

func TestGenericGrantsCarryResourceAndEncoding(t *testing.T) {
	for _, encoding := range []string{oauthprovider.Form, oauthprovider.JSON} {
		t.Run(encoding, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				grant := map[string]string{}
				if encoding == oauthprovider.Form {
					if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
						t.Error("wrong form content type")
					}
					_ = r.ParseForm()
					for k := range r.Form {
						grant[k] = r.Form.Get(k)
					}
				} else {
					_ = json.NewDecoder(r.Body).Decode(&grant)
				}
				if grant["resource"] != "https://mcp.example/mcp" || grant["client_id"] != "client" {
					t.Error("missing resource/client binding")
				}
				_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "access", TokenType: "Bearer"})
			}))
			defer srv.Close()
			p := CustodySpec{Provider: "custom", TokenURL: srv.URL, Resource: "https://mcp.example/mcp", ExchangeEncoding: encoding, RefreshEncoding: encoding}
			if _, err := ExchangeCode(context.Background(), p, "code", "verifier", "client", "http://127.0.0.1:50000/callback"); err != nil {
				t.Fatal(err)
			}
			if _, err := RefreshTokens(context.Background(), p, "refresh", "client"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTokenResponseErrorsAreSanitized(t *testing.T) {
	for name, body := range map[string]string{
		"oauth error on HTTP 200": `{"error":"invalid_grant","error_description":"secret-canary"}`,
		"unknown error":           `{"error":"secret-canary"}`,
		"malformed token":         `{"access_token":123,"secret-canary":`,
		"wrong token type":        `{"access_token":"secret-canary","token_type":"DPoP"}`,
		"negative lifetime":       `{"access_token":"secret-canary","expires_in":-1}`,
		"overflowing lifetime":    `{"access_token":"secret-canary","expires_in":9223372036854775807}`,
		"oversized":               strings.Repeat("secret-canary", 100000),
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer srv.Close()
			_, err := RefreshTokens(context.Background(), CustodySpec{TokenURL: srv.URL}, "refresh", "client")
			if err == nil || strings.Contains(err.Error(), "secret-canary") {
				t.Fatal("token error failed closed/sanitization contract")
			}
			if name == "oauth error on HTTP 200" && !IsPermanentTokenError(err) {
				t.Fatal("GitHub-style invalid grant not treated as permanent")
			}
		})
	}
}

func TestTokenGrantRefusesRedirect(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	if _, err := RefreshTokens(context.Background(), CustodySpec{TokenURL: source.URL}, "refresh", "client"); err == nil {
		t.Fatal("token redirect followed")
	}
	if leaked.Load() != 0 {
		t.Fatal("refresh material sent to redirected endpoint")
	}
}

func TestDeviceSlowDownAndExpiry(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		polls.Add(1)
		_, _ = w.Write([]byte(`{"error":"slow_down"}`))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	_, err := PollDeviceAuthorization(ctx, CustodySpec{TokenURL: srv.URL, ExchangeEncoding: oauthprovider.Form}, DeviceAuthorization{DeviceCode: "private", ExpiresIn: 30, Interval: 1})
	if err == nil || polls.Load() != 1 {
		t.Fatal("device polling did not honor slow_down/cancellation")
	}
}
