package orgauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCallbackBindsStateIssuerAndConsumesOnlyOnce(t *testing.T) {
	redirect := "http://127.0.0.1:40000/oidc/callback"
	c := newCallback(redirect, "https://issuer.example", "expected-state")
	for _, query := range []string{
		"state=wrong&code=secret", "state=expected-state&state=wrong&code=secret", "state=expected-state&code=one&code=two",
		"state=expected-state&code=secret&error=access_denied", "state=expected-state&code=secret&iss=https://wrong.example",
		"state=expected-state&code=", "state=expected-state&code=%", strings.Repeat("x", 8193),
	} {
		r := httptest.NewRequest(http.MethodGet, redirect+"?"+query, nil)
		w := httptest.NewRecorder()
		c.ServeHTTP(w, r)
		if w.Code != 400 || len(c.result) != 0 || strings.Contains(w.Body.String(), "secret") {
			t.Fatalf("invalid callback consumed or reflected: %d", w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("Content-Security-Policy") == "" {
			t.Fatal("missing browser security headers")
		}
	}
	q := url.Values{"state": {"expected-state"}, "code": {"valid-code"}, "iss": {"https://issuer.example"}}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Host = "attacker.example" },
		func(r *http.Request) { r.Method = http.MethodPost },
		func(r *http.Request) { r.URL.Path = "/elsewhere" },
	} {
		r := httptest.NewRequest(http.MethodGet, redirect+"?"+q.Encode(), nil)
		mutate(r)
		w := httptest.NewRecorder()
		c.ServeHTTP(w, r)
		if w.Code != 400 || len(c.result) != 0 {
			t.Fatal("unbound callback accepted")
		}
	}
	for _, want := range []int{200, 409} {
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest(http.MethodGet, redirect+"?"+q.Encode(), nil))
		if w.Code != want {
			t.Fatalf("callback status = %d, want %d", w.Code, want)
		}
	}
	if len(c.result) != 1 || (<-c.result).code != "valid-code" {
		t.Fatal("callback replay consumed twice")
	}
}

func TestCallbackDenialAndLoginCancellationOptions(t *testing.T) {
	c := newCallback("http://127.0.0.1:40000/oidc/callback", "https://issuer.example", "state")
	w := httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:40000/oidc/callback?state=state&error=denied&error_description=PRIVATE-CANARY", nil))
	if w.Code != 200 || !(<-c.result).denied || strings.Contains(w.Body.String(), "PRIVATE-CANARY") {
		t.Fatal("denial not handled safely")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Login(ctx, nil, "", nil); err == nil {
		t.Fatal("invalid login options accepted")
	}
}
