package sandbox

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/credhelper/credproto"
	"github.com/ejpir/gantry/internal/sandbox/oauthbridge"
	"github.com/ejpir/gantry/internal/sandbox/oauthtokens"
)

// newTestCustody builds a manager with the guest push and port-binding
// faked; the OAuth token endpoint is an httptest server.
func newTestCustody(t *testing.T, tokenSrv *httptest.Server) (*custodyManager, *[][]byte) {
	t.Helper()
	t.Setenv("GANTRY_OAUTH_TOKEN_URL_CLAUDE", tokenSrv.URL)
	var mu sync.Mutex
	var pushes [][]byte
	cm := newCustodyManager(&broker{}, oauthtokens.New())
	cm.ensurePort = func(int) {}
	cm.pushAuthFile = func(provider string, tok oauthbridge.TokenResponse) error {
		set, _ := cm.registry.Get(provider)
		content, err := oauthbridge.RenderGuestAuthFile(provider, tok, set.Expiry)
		if err != nil {
			return err
		}
		mu.Lock()
		pushes = append(pushes, content)
		mu.Unlock()
		return nil
	}
	return cm, &pushes
}

func beginReq(state string) credproto.Request {
	return credproto.Request{
		Op:           credproto.OpOAuthBegin,
		Provider:     "claude",
		State:        state,
		Challenge:    "ch",
		Verifier:     "verifier-1",
		ClientID:     "client-1",
		RedirectURI:  "http://127.0.0.1:8485/callback",
		AuthorizeURL: "https://claude.ai/oauth/authorize?...",
	}
}

func TestCustodyBeginCallbackStatusFlow(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var grant map[string]string
		_ = json.NewDecoder(r.Body).Decode(&grant)
		if grant["code"] != "the-code" || grant["code_verifier"] != "verifier-1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(oauthbridge.TokenResponse{
			AccessToken: "custody-at", RefreshToken: "custody-rt", ExpiresIn: 3600,
		})
	}))
	t.Cleanup(tokenSrv.Close)
	cm, pushes := newTestCustody(t, tokenSrv)

	resp := cm.handleOAuthOp(beginReq("state-1"))
	if resp.Error != "" {
		t.Fatalf("begin: %s", resp.Error)
	}
	st := cm.handleOAuthOp(credproto.Request{Op: credproto.OpOAuthStatus, Provider: "claude", State: "state-1"})
	if st.Message != "pending" {
		t.Fatalf("status before callback = %+v, want pending", st)
	}

	cb, _ := url.Parse("http://127.0.0.1:8485/callback?code=the-code&state=state-1")
	if !cm.consumeCallback(8485, cb) {
		t.Fatal("callback not consumed")
	}
	st = cm.handleOAuthOp(credproto.Request{Op: credproto.OpOAuthStatus, Provider: "claude", State: "state-1"})
	if !st.OK {
		t.Fatalf("status after callback = %+v, want OK", st)
	}

	set, held := cm.registry.Get("claude")
	if !held || set.AccessToken != "custody-at" || set.RefreshToken != "custody-rt" || set.ClientID != "client-1" {
		t.Fatalf("registry = %+v, %v", set, held)
	}
	// The guest got the access token + sentinel — never the refresh token.
	if len(*pushes) != 1 {
		t.Fatalf("pushes = %d", len(*pushes))
	}
	pushed := string((*pushes)[0])
	if !strings.Contains(pushed, "custody-at") || !strings.Contains(pushed, oauthbridge.SentinelRefresh) {
		t.Fatalf("guest auth file = %s", pushed)
	}
	if strings.Contains(pushed, "custody-rt") {
		t.Fatal("guest auth file contains the real refresh token")
	}
}

func TestCustodyUnknownStateFallsThroughToBridge(t *testing.T) {
	cm, _ := newTestCustody(t, httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	cb, _ := url.Parse("http://127.0.0.1:8485/callback?code=x&state=someone-else")
	if cm.consumeCallback(8485, cb) {
		t.Fatal("unknown-state callback consumed — the transparent bridge must replay it")
	}
}

func TestCustodyBeginValidation(t *testing.T) {
	cm, _ := newTestCustody(t, httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	if resp := cm.handleOAuthOp(credproto.Request{Op: credproto.OpOAuthBegin, Provider: "gemini"}); resp.Error == "" {
		t.Fatal("unsupported provider accepted")
	}
	bad := beginReq("s2")
	bad.RedirectURI = "http://evil.example.com/callback"
	if resp := cm.handleOAuthOp(bad); !strings.Contains(resp.Error, "loopback") {
		t.Fatalf("non-loopback redirect: %q", resp.Error)
	}
}

func TestCustodyProviderErrorSurfaces(t *testing.T) {
	cm, _ := newTestCustody(t, httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	_ = cm.handleOAuthOp(beginReq("state-err"))
	cb, _ := url.Parse("http://127.0.0.1:8485/callback?error=access_denied&state=state-err")
	if !cm.consumeCallback(8485, cb) {
		t.Fatal("error callback not consumed")
	}
	st := cm.handleOAuthOp(credproto.Request{Op: credproto.OpOAuthStatus, Provider: "claude", State: "state-err"})
	if st.Error == "" || !strings.Contains(st.Error, "access_denied") {
		t.Fatalf("status = %+v, want the provider error", st)
	}
	if _, held := cm.registry.Get("claude"); held {
		t.Fatal("failed login stored a token set")
	}
}

func TestCustodyRefreshLoopPushesRotation(t *testing.T) {
	var grantCount int
	var mu sync.Mutex
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var grant map[string]string
		_ = json.NewDecoder(r.Body).Decode(&grant)
		mu.Lock()
		grantCount++
		n := grantCount
		mu.Unlock()
		if grant["grant_type"] == "refresh_token" {
			_ = json.NewEncoder(w).Encode(oauthbridge.TokenResponse{
				AccessToken: "at-refreshed", RefreshToken: "rt-rotated", ExpiresIn: 3600,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(oauthbridge.TokenResponse{
			AccessToken: "at-initial", RefreshToken: "rt-1", ExpiresIn: 3600,
		})
		_ = n
	}))
	t.Cleanup(tokenSrv.Close)
	cm, pushes := newTestCustody(t, tokenSrv)

	// Seed a nearly-expired set; the loop should refresh it promptly.
	if err := cm.registry.Put(oauthtokens.TokenSet{
		Provider: "claude", AccessToken: "at-initial", RefreshToken: "rt-1",
		ClientID: "client-1", Expiry: time.Now().Add(30 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	cm.startRefreshLoop("claude")

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		set, _ := cm.registry.Get("claude")
		if set.AccessToken == "at-refreshed" {
			if set.RefreshToken != "rt-rotated" {
				t.Fatalf("rotated refresh token not re-captured: %+v", set)
			}
			mu.Lock()
			n := len(*pushes)
			mu.Unlock()
			if n < 1 {
				t.Fatal("refresh did not push the guest auth file")
			}
			last := string((*pushes)[n-1])
			if !strings.Contains(last, "at-refreshed") {
				t.Fatalf("pushed file lacks the refreshed token: %s", last)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("refresh loop never refreshed the nearly-expired set")
}
