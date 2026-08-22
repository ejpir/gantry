package oauthbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockTokenEndpoint records the grant and replies with a token set.
func mockTokenEndpoint(t *testing.T, status int, resp TokenResponse) (*httptest.Server, *map[string]string) {
	t.Helper()
	var lastGrant map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&lastGrant)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &lastGrant
}

func TestExchangeCodePostsGrant(t *testing.T) {
	srv, grant := mockTokenEndpoint(t, http.StatusOK, TokenResponse{
		AccessToken: "at-1", RefreshToken: "rt-1", ExpiresIn: 3600,
	})
	spec := CustodySpec{TokenURL: srv.URL}
	tok, err := ExchangeCode(context.Background(), spec, "the-code", "the-verifier", "client-1", "http://127.0.0.1:8485/callback")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at-1" || tok.RefreshToken != "rt-1" || tok.ExpiresIn != 3600 {
		t.Fatalf("token = %+v", tok)
	}
	g := *grant
	if g["grant_type"] != "authorization_code" || g["code"] != "the-code" ||
		g["code_verifier"] != "the-verifier" || g["client_id"] != "client-1" ||
		g["redirect_uri"] != "http://127.0.0.1:8485/callback" {
		t.Fatalf("grant = %v", g)
	}
}

func TestRefreshTokensPostsGrant(t *testing.T) {
	srv, grant := mockTokenEndpoint(t, http.StatusOK, TokenResponse{
		AccessToken: "at-2", RefreshToken: "rt-2", ExpiresIn: 3600,
	})
	spec := CustodySpec{TokenURL: srv.URL}
	tok, err := RefreshTokens(context.Background(), spec, "rt-1", "client-1")
	if err != nil {
		t.Fatal(err)
	}
	if tok.RefreshToken != "rt-2" {
		t.Fatalf("rotated refresh not captured: %+v", tok)
	}
	g := *grant
	if g["grant_type"] != "refresh_token" || g["refresh_token"] != "rt-1" {
		t.Fatalf("grant = %v", g)
	}
}

func TestCodexUsesProviderContractAndJWTExpiry(t *testing.T) {
	idToken := testJWT(t, map[string]any{
		"exp":                         float64(time.Now().Add(time.Hour).Unix()),
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "acct-42"},
	})
	accessToken := testJWT(t, map[string]any{"exp": float64(time.Now().Add(30 * time.Minute).Unix())})
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/x-www-form-urlencoded") {
				t.Errorf("exchange Content-Type = %q", got)
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code_verifier") != "verifier" {
				t.Errorf("exchange form = %v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: accessToken, RefreshToken: "refresh", IDToken: idToken})
			return
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("refresh Content-Type = %q", got)
		}
		var grant map[string]string
		_ = json.NewDecoder(r.Body).Decode(&grant)
		if grant["grant_type"] != "refresh_token" {
			t.Errorf("refresh grant = %v", grant)
		}
		// Codex refresh responses may omit id_token; the caller retains the
		// previous one from custody storage.
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: accessToken, RefreshToken: "refresh-2"})
	}))
	t.Cleanup(srv.Close)
	spec := custodySpecs["codex"]
	spec.TokenURL = srv.URL
	tok, err := ExchangeCode(context.Background(), spec, "code", "verifier", "client", "http://localhost:1455/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccountID != "acct-42" || tok.ExpiryAt(time.Now()).IsZero() {
		t.Fatalf("normalized codex token = %+v", tok)
	}
	if _, err := RefreshTokens(context.Background(), spec, tok.RefreshToken, "client"); err != nil {
		t.Fatal(err)
	}
}

func TestTokenEndpointErrorCarriesStatusNotBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","secret":"canary"}`))
	}))
	t.Cleanup(srv.Close)
	_, err := RefreshTokens(context.Background(), CustodySpec{TokenURL: srv.URL}, "rt", "cid")
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("err = %v, want status mention", err)
	}
	if strings.Contains(err.Error(), "canary") {
		t.Fatalf("error leaked the response body: %v", err)
	}
}

func TestCustodySpecOverride(t *testing.T) {
	t.Setenv("GANTRY_OAUTH_TOKEN_URL_CLAUDE", "http://127.0.0.1:9999/token")
	spec, ok := CustodySpecFor("claude")
	if !ok || spec.TokenURL != "http://127.0.0.1:9999/token" {
		t.Fatalf("override = %+v, %v", spec, ok)
	}
	if _, ok := CustodySpecFor("unknown-provider"); ok {
		t.Fatal("unknown provider got a custody spec")
	}
}

func TestRenderGuestAuthFile(t *testing.T) {
	expiry := time.Unix(1700000000, 0)
	for _, provider := range []string{"claude", "codex"} {
		tok := TokenResponse{AccessToken: "at-x"}
		if provider == "codex" {
			tok.IDToken = testJWT(t, map[string]any{"email": "dev@example.com"})
			tok.AccountID = "acct-1"
		}
		raw, err := RenderGuestAuthFile(provider, tok, expiry)
		if err != nil {
			t.Fatal(err)
		}
		s := string(raw)
		if !strings.Contains(s, "at-x") {
			t.Fatalf("%s: access token missing from %s", provider, s)
		}
		if !strings.Contains(s, SentinelRefresh) {
			t.Fatalf("%s: sentinel refresh missing from %s", provider, s)
		}
		if provider == "codex" {
			for _, want := range []string{`"auth_mode": "chatgpt"`, `"id_token"`, `"account_id": "acct-1"`, `"last_refresh"`} {
				if !strings.Contains(s, want) {
					t.Fatalf("codex auth file missing %s: %s", want, s)
				}
			}
		}
	}
	if _, err := RenderGuestAuthFile("codex", TokenResponse{AccessToken: "at"}, expiry); err == nil {
		t.Fatal("codex rendered without its required id_token")
	}
	if _, err := RenderGuestAuthFile("unknown", TokenResponse{}, expiry); err == nil {
		t.Fatal("unknown provider rendered")
	}
}

func testJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}
