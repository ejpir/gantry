package sandbox

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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
	t.Cleanup(tokenSrv.Close)
	t.Setenv("GANTRY_OAUTH_TOKEN_URL_CLAUDE", tokenSrv.URL)
	var mu sync.Mutex
	var pushes [][]byte
	cm := newCustodyManager(&broker{}, oauthtokens.New())
	cm.ensurePort = func(int) bool { return true }
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

func TestCustodyCallbackIsClaimedExactlyOnce(t *testing.T) {
	var exchanges atomic.Int32
	release := make(chan struct{})
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		<-release
		_ = json.NewEncoder(w).Encode(oauthbridge.TokenResponse{
			AccessToken: "at", RefreshToken: "rt", ExpiresIn: 3600,
		})
	}))
	t.Cleanup(tokenSrv.Close)
	cm, _ := newTestCustody(t, tokenSrv)
	if resp := cm.begin(beginReq("one-shot")); resp.Error != "" {
		t.Fatal(resp.Error)
	}
	callback, _ := url.Parse("http://127.0.0.1:8485/callback?code=code&state=one-shot")
	if !cm.consumeCallback(8485, callback) {
		t.Fatal("first callback was not consumed")
	}
	if !cm.consumeCallback(8485, callback) {
		t.Fatal("duplicate callback was not consumed")
	}
	deadline := time.Now().Add(time.Second)
	for exchanges.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := exchanges.Load(); got != 1 {
		t.Fatalf("token exchanges = %d, want exactly one", got)
	}
	close(release)
	if status := cm.status(credproto.Request{Provider: "claude", State: "one-shot"}); !status.OK {
		t.Fatalf("status = %+v", status)
	}
	// Completed results remain idempotently consumed instead of falling
	// through to the transparent bridge and replaying the code into the guest.
	if !cm.consumeCallback(8485, callback) {
		t.Fatal("completed duplicate callback fell through")
	}
}

func TestCustodyPendingFlowsAreBoundedAndPortFailureIsLoud(t *testing.T) {
	cm, _ := newTestCustody(t, httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	cm.ensurePort = func(int) bool { return false }
	if resp := cm.begin(beginReq("bind-failure")); !strings.Contains(resp.Error, "could not be opened") {
		t.Fatalf("bind failure = %+v", resp)
	}
	cm.mu.Lock()
	if len(cm.flows) != 0 {
		t.Fatalf("failed bind retained flows: %d", len(cm.flows))
	}
	cm.mu.Unlock()

	cm.ensurePort = func(int) bool { return true }
	for i := 0; i < maxCustodyFlows; i++ {
		if resp := cm.begin(beginReq(fmt.Sprintf("state-%d", i))); resp.Error != "" {
			t.Fatalf("begin %d: %s", i, resp.Error)
		}
	}
	if resp := cm.begin(beginReq("overflow")); !strings.Contains(resp.Error, "too many") {
		t.Fatalf("overflow = %+v", resp)
	}
	cm.mu.Lock()
	flows := make([]*custodyFlow, 0, len(cm.flows))
	for _, flow := range cm.flows {
		flows = append(flows, flow)
	}
	cm.mu.Unlock()
	for _, flow := range flows {
		cm.finish(flow, fmt.Errorf("test cleanup"))
	}
}

func TestCustodyRestartRestoresGuestAuthFile(t *testing.T) {
	cm, pushes := newTestCustody(t, httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	if err := cm.registry.Put(oauthtokens.TokenSet{
		Provider: "claude", AccessToken: "restored-at", Expiry: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	cm.restoreRestart()
	if len(*pushes) != 1 {
		t.Fatalf("restored auth push count = %d, want 1", len(*pushes))
	}
	if !strings.Contains(string((*pushes)[0]), "restored-at") {
		t.Fatal("restored auth push did not contain the current access token")
	}
}

func TestCustodyRefreshLoopReapsProviderSlot(t *testing.T) {
	cm, _ := newTestCustody(t, httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	if err := cm.registry.Put(oauthtokens.TokenSet{Provider: "claude", AccessToken: "non-expiring"}); err != nil {
		t.Fatal(err)
	}
	cm.startRefreshLoop("claude")
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		cm.mu.Lock()
		_, running := cm.loops["claude"]
		cm.mu.Unlock()
		if !running {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("completed refresh loop retained its provider slot")
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
