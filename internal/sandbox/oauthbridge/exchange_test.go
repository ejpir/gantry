package oauthbridge

import (
	"context"
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
	tok := TokenResponse{AccessToken: "at-x"}
	for _, provider := range []string{"claude", "codex"} {
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
	}
	if _, err := RenderGuestAuthFile("unknown", tok, expiry); err == nil {
		t.Fatal("unknown provider rendered")
	}
}
