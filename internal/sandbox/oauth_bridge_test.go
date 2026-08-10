package sandbox

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOAuthCallbackPorts(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []int
	}{
		{
			name: "codex encoded redirect_uri",
			text: `Open this URL: https://auth.openai.com/oauth/authorize?response_type=code&client_id=abc&redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback&state=xyz`,
			want: []int{1455},
		},
		{
			name: "pi plain redirect_uri",
			text: `Visit: https://claude.ai/oauth/authorize?redirect_uri=http://localhost:53692/callback&client_id=z`,
			want: []int{53692},
		},
		{
			name: "claude encoded random port",
			text: `redirect_uri=http%3A%2F%2Flocalhost%3A51234%2Fcallback`,
			want: []int{51234},
		},
		{
			name: "bare printed callback URL",
			text: "listening on http://127.0.0.1:1455/auth/callback — waiting",
			want: []int{1455},
		},
		{
			name: "non-localhost redirect ignored",
			text: `redirect_uri=https%3A%2F%2Fevil.example%2Fcallback`,
			want: nil,
		},
		{
			name: "https loopback scheme ignored",
			text: `redirect_uri=https%3A%2F%2Flocalhost%3A1455%2Fcallback`,
			want: nil,
		},
		{
			name: "privileged port ignored",
			text: `redirect_uri=http%3A%2F%2Flocalhost%3A80%2Fcallback`,
			want: nil,
		},
		{
			name: "arbitrary application port ignored",
			text: `redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback`,
			want: nil,
		},
		{
			name: "unrelated noise",
			text: "npm warn deprecated foo@1.2.3\nserver on http://localhost:3000/health",
			want: nil,
		},
		{
			name: "split across writes reassembled",
			text: "redirect_uri=http%3A%2F%2Floc" + "alhost%3A1455%2Fauth%2Fcallback",
			want: []int{1455},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := oauthCallbackPorts(tc.text)
			sort.Ints(got)
			if len(got) != len(tc.want) {
				t.Fatalf("ports = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ports = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestOAuthCallbackPortsLocalhostHealthNotCallback(t *testing.T) {
	// A loopback URL with a non-callback path must not arm the bridge,
	// whether it is bare or appears as a redirect_uri parameter.
	if got := oauthCallbackPorts("curl http://localhost:3000/health && break"); len(got) != 0 {
		t.Fatalf("ports = %v, want none", got)
	}
	if got := oauthCallbackPorts("redirect_uri=http%3A%2F%2Flocalhost%3A55000%2Fhealth"); len(got) != 0 {
		t.Fatalf("non-callback redirect_uri ports = %v, want none", got)
	}
}

func testBridge(t *testing.T, replay func(port int, uri string) (oauthReplayResult, error)) *oauthBridge {
	t.Helper()
	b := &oauthBridge{
		replay:           replay,
		logf:             func(string, ...any) {},
		listeners:        map[int]*oauthListener{},
		failed:           map[int]bool{},
		replaySlots:      make(chan struct{}, oauthMaxConcurrentReplays),
		replayTimeout:    oauthReplayTimeout,
		listenerLifetime: time.Minute,
	}
	t.Cleanup(func() {
		b.mu.Lock()
		var ports []int
		for p := range b.listeners {
			ports = append(ports, p)
		}
		b.mu.Unlock()
		for _, p := range ports {
			b.closeListener(p)
		}
	})
	return b
}

func freeAllowedOAuthPort(t *testing.T) int {
	t.Helper()
	for port := 55000; port < 65000; port++ {
		ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		_ = ln.Close()
		return port
	}
	t.Fatal("no free OAuth callback port")
	return 0
}

func TestBridgeEndToEndWithFakeGuest(t *testing.T) {
	// Fake the in-sandbox CLI listener: the replay function stands in for
	// the bash /dev/tcp exec, delivering the request to a local HTTP server.
	var gotURI string
	guest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI = r.URL.RequestURI()
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "<html>Sign-in complete</html>")
	}))
	defer guest.Close()

	b := testBridge(t, func(port int, uri string) (oauthReplayResult, error) {
		resp, err := http.Get(guest.URL + uri)
		if err != nil {
			return oauthReplayResult{}, err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return oauthReplayResult{}, err
		}
		return oauthReplayResult{
			status:      resp.StatusCode,
			contentType: resp.Header.Get("Content-Type"),
			location:    resp.Header.Get("Location"),
			body:        body,
		}, nil
	})

	// Sniff a codex-style authorize URL; the bridge must bind 1455-equivalent.
	// Use a free port instead of 1455 to avoid host collisions in CI.
	port := freeAllowedOAuthPort(t)

	var out strings.Builder
	w := b.sniffWriter(&out)
	printed := "open https://provider.example/oauth/authorize?redirect_uri=http%3A%2F%2Flocalhost%3A" +
		fmt.Sprint(port) + "%2Fauth%2Fcallback&state=s3cr3t\n"
	if _, err := w.Write([]byte(printed)); err != nil {
		t.Fatal(err)
	}
	if out.String() != printed {
		t.Fatalf("sniff writer altered output: %q", out.String())
	}

	// Wait for the async listener bind.
	deadline := time.Now().Add(3 * time.Second)
	for {
		b.mu.Lock()
		_, ok := b.listeners[port]
		b.mu.Unlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bridge did not bind the host listener")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Host browser follows the provider redirect to the loopback callback.
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/auth/callback?code=abc123&state=s3cr3t", port))
	if err != nil {
		t.Fatalf("browser callback: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "Sign-in complete") {
		t.Fatalf("guest response not relayed: %s", body)
	}
	if gotURI != "/auth/callback?code=abc123&state=s3cr3t" {
		t.Fatalf("guest saw URI %q", gotURI)
	}

	// code= was delivered: the listener must close shortly after.
	deadline = time.Now().Add(5 * time.Second)
	for {
		b.mu.Lock()
		_, ok := b.listeners[port]
		b.mu.Unlock()
		if !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener did not close after delivering the code")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestBridgeForwardsGuestRedirect(t *testing.T) {
	// Codex answers /auth/callback with a 302 to its result page. The
	// Location header must reach the browser, or it renders a blank page.
	b := testBridge(t, func(port int, uri string) (oauthReplayResult, error) {
		return oauthReplayResult{status: 302, location: "/auth/success", contentType: "text/plain; charset=utf-8"}, nil
	})
	l := &oauthListener{port: 1}
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=s", nil)
	rec := httptest.NewRecorder()
	b.handleCallback(l)(rec, req)
	if rec.Code != 302 {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/auth/success" {
		t.Fatalf("Location = %q, want /auth/success (blank-page regression)", loc)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type = %q, guest type not preserved", ct)
	}
}

func TestBridgeReplayFailureReturnsBadGateway(t *testing.T) {
	b := testBridge(t, func(port int, uri string) (oauthReplayResult, error) {
		return oauthReplayResult{}, fmt.Errorf("in-sandbox replay exited 97: cannot connect")
	})
	l := &oauthListener{port: 1}
	req := httptest.NewRequest(http.MethodGet, "/callback?code=x", nil)
	rec := httptest.NewRecorder()
	b.handleCallback(l)(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "could not deliver") {
		t.Fatalf("unhelpful error page: %s", rec.Body.String())
	}
}

func TestBridgeRejectsNonGET(t *testing.T) {
	b := testBridge(t, func(port int, uri string) (oauthReplayResult, error) {
		t.Fatal("replay must not run for POST")
		return oauthReplayResult{}, nil
	})
	l := &oauthListener{port: 1}
	req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader("x"))
	rec := httptest.NewRecorder()
	b.handleCallback(l)(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestBridgeCapsConcurrentReplays(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, oauthMaxConcurrentReplays)
	var calls atomic.Int32
	b := testBridge(t, func(port int, uri string) (oauthReplayResult, error) {
		calls.Add(1)
		started <- struct{}{}
		<-release
		return oauthReplayResult{status: http.StatusOK, body: []byte("ok")}, nil
	})
	l := &oauthListener{port: 1455}
	done := make(chan struct{}, oauthMaxConcurrentReplays)
	for i := 0; i < oauthMaxConcurrentReplays; i++ {
		go func(i int) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/callback?attempt=%d", i), nil)
			b.handleCallback(l)(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("replay %d status = %d, want 200", i, rec.Code)
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < oauthMaxConcurrentReplays; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("replay did not start")
		}
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/callback?attempt=overflow", nil)
	b.handleCallback(l)(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("overflow replay status = %d, want 429", rec.Code)
	}
	if got := calls.Load(); got != oauthMaxConcurrentReplays {
		t.Fatalf("replay calls = %d, want capped at %d", got, oauthMaxConcurrentReplays)
	}
	close(release)
	for i := 0; i < oauthMaxConcurrentReplays; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("replay did not unwind")
		}
	}
}

func TestBridgeReplayTimeoutKeepsSlotCharged(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	b := testBridge(t, func(port int, uri string) (oauthReplayResult, error) {
		close(started)
		<-release
		return oauthReplayResult{status: http.StatusOK}, nil
	})
	b.replayTimeout = 20 * time.Millisecond
	l := &oauthListener{port: 1455}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/callback?code=slow", nil)
	begin := time.Now()
	b.handleCallback(l)(rec, req)
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("timeout status = %d, want 504", rec.Code)
	}
	if elapsed := time.Since(begin); elapsed > time.Second {
		t.Fatalf("timeout response took %s", elapsed)
	}
	<-started
	if got := len(b.replaySlots); got != 1 {
		t.Fatalf("timed-out replay released slot while still running: %d", got)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for len(b.replaySlots) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("replay slot was not released after underlying replay stopped")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBridgeRejectsOversizeReplayResponse(t *testing.T) {
	b := testBridge(t, func(port int, uri string) (oauthReplayResult, error) {
		return oauthReplayResult{
			status: http.StatusOK,
			body:   []byte(strings.Repeat("x", oauthMaxReplayResponseSize+1)),
		}, nil
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/callback?code=large", nil)
	b.handleCallback(&oauthListener{port: 1455})(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("oversize response status = %d, want 502", rec.Code)
	}
	if rec.Body.Len() >= oauthMaxReplayResponseSize {
		t.Fatalf("oversize guest body was relayed: %d bytes", rec.Body.Len())
	}

	var capture oauthCapture
	payload := []byte(strings.Repeat("y", oauthMaxReplayResponseSize+4096))
	if n, err := capture.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("bounded capture write = %d, %v", n, err)
	}
	if !capture.overflow || capture.buf.Len() != oauthMaxReplayResponseSize {
		t.Fatalf("bounded capture: overflow=%v retained=%d", capture.overflow, capture.buf.Len())
	}
	if _, err := parseRawHTTPResponse(payload); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize raw response error = %v", err)
	}
}

func TestBridgeRejectsOversizeCallbackURI(t *testing.T) {
	b := testBridge(t, func(port int, uri string) (oauthReplayResult, error) {
		t.Fatal("oversize callback must be rejected before replay")
		return oauthReplayResult{}, nil
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+strings.Repeat("x", oauthMaxRequestURIBytes), nil)
	b.handleCallback(&oauthListener{port: 1455})(rec, req)
	if rec.Code != http.StatusRequestURITooLong {
		t.Fatalf("oversize callback status = %d, want 414", rec.Code)
	}
}

func TestBridgeListenerLimit(t *testing.T) {
	b := testBridge(t, nil)
	for i := 0; i < oauthMaxActiveListeners; i++ {
		port := 55000 + i
		b.listeners[port] = &oauthListener{port: port, ln: closedTestListener{}}
	}
	target := 56000
	b.ensureListener(target)
	b.mu.Lock()
	_, added := b.listeners[target]
	count := len(b.listeners)
	// The fake listeners were not started by serve; remove them before
	// testBridge's cleanup attempts to close the map.
	b.listeners = map[int]*oauthListener{}
	b.mu.Unlock()
	if added || count != oauthMaxActiveListeners {
		t.Fatalf("listeners after overflow: added=%v count=%d", added, count)
	}
}

type closedTestListener struct{}

func (closedTestListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (closedTestListener) Close() error              { return nil }
func (closedTestListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestParseRawHTTPResponse(t *testing.T) {
	raw := "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, world!\nclient: exec exited, status 0\n"
	res, err := parseRawHTTPResponse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if res.status != 200 {
		t.Fatalf("status = %d", res.status)
	}
	if string(res.body) != "Hello, world!" {
		t.Fatalf("body = %q (session trailer leaked into Content-Length body)", res.body)
	}
	if res.contentType != "text/html" {
		t.Fatalf("contentType = %q", res.contentType)
	}

	// Close-delimited body without Content-Length.
	raw2 := "HTTP/1.0 302 Found\r\nLocation: /auth/success\r\n\r\n"
	res, err = parseRawHTTPResponse([]byte(raw2))
	if err != nil || res.status != 302 {
		t.Fatalf("status %d err %v", res.status, err)
	}
	if res.location != "/auth/success" {
		t.Fatalf("location = %q (redirect target lost)", res.location)
	}

	// Node-style chunked response (claude/pi listeners).
	raw3 := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"8\r\nSign-in \r\n8\r\ncomplete\r\n0\r\n\r\n"
	res, err = parseRawHTTPResponse([]byte(raw3))
	if err != nil || res.status != 200 {
		t.Fatalf("chunked: status %d err %v", res.status, err)
	}
	if string(res.body) != "Sign-in complete" {
		t.Fatalf("chunked body = %q", res.body)
	}

	if _, err := parseRawHTTPResponse([]byte("garbage")); err == nil {
		t.Fatal("expected error for non-HTTP input")
	}
	if _, err := parseRawHTTPResponse([]byte("oops\r\n\r\nbody")); err == nil {
		t.Fatal("expected error for malformed status line")
	}
}

func TestDecodeChunkedBodyRejectsOverflowSize(t *testing.T) {
	if _, err := decodeChunkedBody([]byte("7fffffffffffffff\r\nx\r\n")); err == nil {
		t.Fatal("MaxInt64 chunk size must be rejected")
	}
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7fffffffffffffff\r\nx\r\n"
	if _, err := parseRawHTTPResponse([]byte(raw)); err == nil || !strings.Contains(err.Error(), "decode chunked") {
		t.Fatalf("malformed chunked response error = %v", err)
	}
}

func TestSniffWriterDedupesAndBindFailure(t *testing.T) {
	b := testBridge(t, nil)

	// Bind a port ourselves so the bridge's bind fails.
	port := freeAllowedOAuthPort(t)
	freeLn, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = freeLn.Close() }()

	b.ensureListener(port)
	b.ensureListener(port) // idempotent, no panic, no double log

	b.mu.Lock()
	_, bound := b.listeners[port]
	failed := b.failed[port]
	b.mu.Unlock()
	if bound {
		t.Fatal("bridge bound a port that was already in use")
	}
	if !failed {
		t.Fatal("bind failure not remembered")
	}
}

func TestNewOAuthBridgeDefaultsOnWithExplicitOverrides(t *testing.T) {
	t.Setenv("GANTRY_OAUTH_BRIDGE", "")
	if newOAuthBridge(&broker{}) == nil {
		t.Fatal("bridge must default on for legacy and default configs")
	}
	disabled := false
	if newOAuthBridge(&broker{cfg: RunConfig{OAuthBridge: &disabled}}) != nil {
		t.Fatal("persisted oauth_bridge=false did not disable bridge")
	}
	t.Setenv("GANTRY_OAUTH_BRIDGE", "1")
	if newOAuthBridge(&broker{cfg: RunConfig{OAuthBridge: &disabled}}) == nil {
		t.Fatal("GANTRY_OAUTH_BRIDGE=1 must override a persisted opt-out")
	}
	t.Setenv("GANTRY_OAUTH_BRIDGE", "0")
	if newOAuthBridge(&broker{}) != nil {
		t.Fatal("GANTRY_OAUTH_BRIDGE=0 must override default activation")
	}
}

// TestDevTCPReplayScriptShape guards the contract the in-guest one-liner
// relies on: positional args, loopback-only target, single GET.
func TestDevTCPReplayScriptShape(t *testing.T) {
	if !strings.Contains(devTCPReplayScript, `/dev/tcp/127.0.0.1/$port`) {
		t.Fatal("script must target guest loopback only")
	}
	if strings.Contains(devTCPReplayScript, "http_proxy") || strings.Contains(devTCPReplayScript, "curl") || strings.Contains(devTCPReplayScript, "wget") {
		t.Fatal("script must not depend on external HTTP tools")
	}
	if !strings.Contains(devTCPReplayScript, "printf 'GET %s HTTP/1.0") {
		t.Fatal("script must issue exactly one GET")
	}
}
