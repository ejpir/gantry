package oauthbridge

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
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
			name: "bare callback suffix and query",
			text: "listening on http://127.0.0.1:55123/auth/callback/final?state=opaque-state",
			want: []int{55123},
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
			got := callbackPorts(tc.text)
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
	if got := callbackPorts("curl http://localhost:3000/health && break"); len(got) != 0 {
		t.Fatalf("ports = %v, want none", got)
	}
	if got := callbackPorts("redirect_uri=http%3A%2F%2Flocalhost%3A55000%2Fhealth"); len(got) != 0 {
		t.Fatalf("non-callback redirect_uri ports = %v, want none", got)
	}
}

func TestOAuthCallbackTargetsCapturePathAndState(t *testing.T) {
	targets := callbackTargets(`Open https://provider.example/authorize?state=s3cr3t%2Fvalue&redirect_uri=http%3A%2F%2Flocalhost%3A55123%2Fauth%2Fcallback`)
	if len(targets) != 1 {
		t.Fatalf("targets = %+v, want one", targets)
	}
	if got := targets[0]; got.port != 55123 || got.path != "/auth/callback" || got.state != "s3cr3t/value" || !got.validateState {
		t.Fatalf("target = %+v", got)
	}

	targets = callbackTargets(`Open http://localhost:55124/auth/callback/final?state=bare-state`)
	if len(targets) != 1 {
		t.Fatalf("bare targets = %+v, want one", targets)
	}
	if got := targets[0]; got.port != 55124 || got.path != "/auth/callback/final" || got.state != "bare-state" || !got.validateState {
		t.Fatalf("bare target = %+v", got)
	}
}

func TestSniffWriterEnrichesStateSplitAcrossWrites(t *testing.T) {
	port := freeAllowedOAuthPort(t)
	b := testBridge(t, func(int, string) (replayResult, error) {
		return replayResult{status: http.StatusOK}, nil
	})
	w := b.SniffWriter(io.Discard)
	first := fmt.Sprintf("https://provider.example/authorize?redirect_uri=http%%3A%%2F%%2Flocalhost%%3A%d%%2Fauth%%2Fcallback", port)
	if _, err := w.Write([]byte(first)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("&state=late-state\n")); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	l := b.listeners[port]
	b.mu.Unlock()
	if l == nil || l.expectedPath != "/auth/callback" || l.expectedState != "late-state" || !l.validateState {
		t.Fatalf("listener expectation was not enriched: %+v", l)
	}
}

func TestSniffWriterExtendsPartialPathAndStateAcrossWrites(t *testing.T) {
	cases := []struct {
		name      string
		first     func(int) string
		second    string
		wantPath  string
		wantState string
	}{
		{
			name:      "state token",
			first:     func(port int) string { return fmt.Sprintf("open http://localhost:%d/auth/callback?state=late-", port) },
			second:    "state\n",
			wantPath:  "/auth/callback",
			wantState: "late-state",
		},
		{
			name:      "path token",
			first:     func(port int) string { return fmt.Sprintf("open http://localhost:%d/auth/callback", port) },
			second:    "/final?state=path-state\n",
			wantPath:  "/auth/callback/final",
			wantState: "path-state",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port := freeAllowedOAuthPort(t)
			b := testBridge(t, nil)
			w := b.SniffWriter(io.Discard)
			if _, err := w.Write([]byte(tc.first(port))); err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte(tc.second)); err != nil {
				t.Fatal(err)
			}
			b.mu.Lock()
			l := b.listeners[port]
			b.mu.Unlock()
			if l == nil || l.expectedPath != tc.wantPath || l.expectedState != tc.wantState || !l.validateState {
				t.Fatalf("listener expectation = %+v, want path=%q state=%q", l, tc.wantPath, tc.wantState)
			}
		})
	}
}

func testBridge(t *testing.T, replay func(port int, uri string) (replayResult, error)) *Bridge {
	t.Helper()
	b := &Bridge{
		replay:           replay,
		logf:             func(string, ...any) {},
		listeners:        map[int]*listener{},
		failed:           map[int]bool{},
		replaySlots:      make(chan struct{}, maxConcurrentReplays),
		replayTimeout:    ReplayTimeout,
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

	b := testBridge(t, func(port int, uri string) (replayResult, error) {
		resp, err := http.Get(guest.URL + uri)
		if err != nil {
			return replayResult{}, err
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return replayResult{status: resp.StatusCode}, nil
	})

	// Sniff a codex-style authorize URL; the bridge must bind 1455-equivalent.
	// Use a free port instead of 1455 to avoid host collisions in CI.
	port := freeAllowedOAuthPort(t)

	var out strings.Builder
	w := b.SniffWriter(&out)
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
	if !strings.Contains(string(body), "OAuth callback delivered") {
		t.Fatalf("host completion page missing: %s", body)
	}
	if strings.Contains(string(body), "Sign-in complete") {
		t.Fatalf("guest-controlled response reached the browser: %s", body)
	}
	assertSafeBrowserHeaders(t, resp.Header)
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

func TestBridgeDoesNotForwardGuestRedirectOrMetadata(t *testing.T) {
	b := testBridge(t, func(port int, uri string) (replayResult, error) {
		raw := "HTTP/1.1 302 Found\r\n" +
			"Content-Type: application/javascript\r\n" +
			"Location: https://attacker.example/from-guest\r\n\r\n" +
			`<script>fetch("http://127.0.0.1:2375/attack")</script>`
		return parseRawHTTPResponse([]byte(raw))
	})
	l := &listener{port: 1}
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=s", nil)
	rec := httptest.NewRecorder()
	b.handleCallback(l)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("guest Location reached browser as %q", loc)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want fixed host type", ct)
	}
	if strings.Contains(rec.Body.String(), "127.0.0.1:2375") || strings.Contains(rec.Body.String(), "script") {
		t.Fatalf("active guest body reached browser: %s", rec.Body.String())
	}
	assertSafeBrowserHeaders(t, rec.Header())
}

func TestBridgeRejectsMismatchedCallbackPathAndState(t *testing.T) {
	var calls atomic.Int32
	b := testBridge(t, func(int, string) (replayResult, error) {
		calls.Add(1)
		return replayResult{status: http.StatusOK}, nil
	})
	l := &listener{port: 55123, expectedPath: "/auth/callback", expectedState: "expected", validateState: true}
	for _, uri := range []string{
		"/other/callback?code=x&state=expected",
		"/auth/callback?code=x&state=wrong",
		"/auth/callback?code=x",
	} {
		rec := httptest.NewRecorder()
		b.handleCallback(l)(rec, httptest.NewRequest(http.MethodGet, uri, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", uri, rec.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("mismatched callbacks reached guest %d times", calls.Load())
	}
	rec := httptest.NewRecorder()
	b.handleCallback(l)(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?code=x&state=expected", nil))
	if rec.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("matching callback status/calls = %d/%d", rec.Code, calls.Load())
	}

	// A state-less URL arms a state-less flow, not a wildcard. This keeps a
	// sandbox that squats on a fixed callback port from receiving another
	// sandbox's callback carrying an unpredictable state.
	l.expectedState = ""
	rec = httptest.NewRecorder()
	b.handleCallback(l)(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?code=x&state=someone-else", nil))
	if rec.Code != http.StatusNotFound || calls.Load() != 1 {
		t.Fatalf("state-less expectation accepted another flow: status/calls = %d/%d", rec.Code, calls.Load())
	}
	rec = httptest.NewRecorder()
	b.handleCallback(l)(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?code=x", nil))
	if rec.Code != http.StatusNotFound || calls.Load() != 1 {
		t.Fatalf("state-less OAuth result was replayed: status/calls = %d/%d", rec.Code, calls.Load())
	}
}

func assertSafeBrowserHeaders(t *testing.T, header http.Header) {
	t.Helper()
	if csp := header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "sandbox") {
		t.Fatalf("unsafe or missing CSP: %q", csp)
	}
	if got := header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := header.Get("Clear-Site-Data"); got != `"cache", "storage"` {
		t.Fatalf("Clear-Site-Data = %q", got)
	}
}

func TestBridgeReplayFailureReturnsBadGateway(t *testing.T) {
	b := testBridge(t, func(port int, uri string) (replayResult, error) {
		return replayResult{}, fmt.Errorf(`in-sandbox replay exited 97: <script>fetch("http://127.0.0.1:2375")</script>`)
	})
	l := &listener{port: 1}
	req := httptest.NewRequest(http.MethodGet, "/callback?code=x", nil)
	rec := httptest.NewRecorder()
	b.handleCallback(l)(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "could not deliver") {
		t.Fatalf("unhelpful error page: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "127.0.0.1:2375") || strings.Contains(rec.Body.String(), "script") {
		t.Fatalf("guest-controlled error detail reached browser: %s", rec.Body.String())
	}
}

func TestBridgeRejectsNonGET(t *testing.T) {
	b := testBridge(t, func(port int, uri string) (replayResult, error) {
		t.Fatal("replay must not run for POST")
		return replayResult{}, nil
	})
	l := &listener{port: 1}
	req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader("x"))
	rec := httptest.NewRecorder()
	b.handleCallback(l)(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestBridgeCapsConcurrentReplays(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, maxConcurrentReplays)
	var calls atomic.Int32
	b := testBridge(t, func(port int, uri string) (replayResult, error) {
		calls.Add(1)
		started <- struct{}{}
		<-release
		return replayResult{status: http.StatusOK}, nil
	})
	l := &listener{port: 1455}
	done := make(chan struct{}, maxConcurrentReplays)
	for i := 0; i < maxConcurrentReplays; i++ {
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
	for i := 0; i < maxConcurrentReplays; i++ {
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
	if got := calls.Load(); got != maxConcurrentReplays {
		t.Fatalf("replay calls = %d, want capped at %d", got, maxConcurrentReplays)
	}
	close(release)
	for i := 0; i < maxConcurrentReplays; i++ {
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
	b := testBridge(t, func(port int, uri string) (replayResult, error) {
		close(started)
		<-release
		return replayResult{status: http.StatusOK}, nil
	})
	b.replayTimeout = 20 * time.Millisecond
	l := &listener{port: 1455}
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
	payload := []byte(strings.Repeat("y", MaxReplayResponseSize+4096))
	if _, err := parseRawHTTPResponse(payload); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize raw response error = %v", err)
	}
}

func TestBridgeRejectsOversizeCallbackURI(t *testing.T) {
	b := testBridge(t, func(port int, uri string) (replayResult, error) {
		t.Fatal("oversize callback must be rejected before replay")
		return replayResult{}, nil
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+strings.Repeat("x", maxRequestURIBytes), nil)
	b.handleCallback(&listener{port: 1455})(rec, req)
	if rec.Code != http.StatusRequestURITooLong {
		t.Fatalf("oversize callback status = %d, want 414", rec.Code)
	}
}

func TestBridgeListenerLimit(t *testing.T) {
	b := testBridge(t, nil)
	for i := 0; i < maxActiveListeners; i++ {
		port := 55000 + i
		b.listeners[port] = &listener{port: port, ln: closedTestListener{}}
	}
	target := 56000
	b.ensureListener(target)
	b.mu.Lock()
	_, added := b.listeners[target]
	count := len(b.listeners)
	// The fake listeners were not started by serve; remove them before
	// testBridge's cleanup attempts to close the map.
	b.listeners = map[int]*listener{}
	b.mu.Unlock()
	if added || count != maxActiveListeners {
		t.Fatalf("listeners after overflow: added=%v count=%d", added, count)
	}
}

type closedTestListener struct{}

func (closedTestListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (closedTestListener) Close() error              { return nil }
func (closedTestListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestReplayViaDevTCPPreservesEmptyRedirectTerminator(t *testing.T) {
	response := "HTTP/1.0 302 Found\r\n" +
		"Server: tiny-http (Rust)\r\n" +
		"Location: http://localhost:1455/success?id_token=opaque\r\n\r\n"
	for _, suffix := range []string{"", "\nclient: task exited, status 0\n"} {
		b := &Bridge{
			exec: func([]string, time.Duration) ([]byte, int, error) {
				return []byte(response + suffix), 0, nil
			},
		}
		res, err := b.replayViaDevTCP(1455, "/auth/callback?code=abc")
		if err != nil {
			t.Fatalf("suffix %q: %v", suffix, err)
		}
		if res.status != http.StatusFound {
			t.Fatalf("suffix %q: response = %+v", suffix, res)
		}
	}
}

func TestParseRawHTTPResponse(t *testing.T) {
	raw := "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, world!\nclient: task exited, status 0\n"
	res, err := parseRawHTTPResponse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if res.status != 200 {
		t.Fatalf("status = %d", res.status)
	}

	// Guest metadata is untrusted and must neither be interpreted nor rejected:
	// the browser always gets a separately constructed host response.
	for _, location := range []string{
		"https://attacker.example/exfil",
		"//attacker.example/from-guest",
		"/%2f%2fattacker.example/from-guest",
	} {
		raw := "HTTP/1.0 302 Found\r\nContent-Type: application/javascript\r\nLocation: " + location + "\r\n\r\n<script>attack()</script>"
		if parsed, err := parseRawHTTPResponse([]byte(raw)); err != nil || parsed.status != http.StatusFound {
			t.Errorf("untrusted metadata changed delivery for Location %q: response=%+v error=%v", location, parsed, err)
		}
	}

	// Session stream transports can turn tiny-http's CRLF response into LF.
	lf := "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n8\nignored!\n0\n\n"
	res, err = parseRawHTTPResponse([]byte(lf))
	if err != nil || res.status != http.StatusOK {
		t.Fatalf("LF response: status %d err %v", res.status, err)
	}

	if _, err := parseRawHTTPResponse([]byte("garbage")); err == nil {
		t.Fatal("expected error for non-HTTP input")
	}
	if _, err := parseRawHTTPResponse([]byte("oops\r\n\r\nbody")); err == nil {
		t.Fatal("expected error for malformed status line")
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

func TestSniffWriterDoesNotReopenClosedListener(t *testing.T) {
	b := testBridge(t, nil)
	port := freeAllowedOAuthPort(t)
	w := b.SniffWriter(io.Discard)
	first := fmt.Sprintf("open https://provider.example/authorize?redirect_uri=http%%3A%%2F%%2Flocalhost%%3A%d%%2Fauth%%2Fcallback", port)
	if _, err := w.Write([]byte(first)); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	l := b.listeners[port]
	b.mu.Unlock()
	if l == nil {
		t.Fatal("initial callback URL did not open listener")
	}
	b.closeExactListener(l)

	// This completes the same buffered URL and therefore enriches its state.
	// Enrichment after one-shot/TTL closure must not recreate the listener.
	if _, err := w.Write([]byte("&state=late-state\nmore output\n")); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	_, reopened := b.listeners[port]
	b.mu.Unlock()
	if reopened {
		t.Fatal("old buffered callback URL reopened a closed listener")
	}
}

func TestSniffWriterConcurrentWrites(t *testing.T) {
	b := testBridge(t, nil)
	port := freeAllowedOAuthPort(t)
	w := b.SniffWriter(io.Discard)
	printed := fmt.Sprintf("open http://localhost:%d/auth/callback?state=concurrent\n", port)

	const writers = 16
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := w.Write([]byte(printed))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	b.mu.Lock()
	l := b.listeners[port]
	b.mu.Unlock()
	if l == nil || l.expectedPath != "/auth/callback" || l.expectedState != "concurrent" {
		t.Fatalf("concurrent scanner result = %+v", l)
	}
}

func TestCustodyListenerFailsClosedAndCannotBePoisoned(t *testing.T) {
	var replayCalls atomic.Int32
	b := testBridge(t, func(int, string) (replayResult, error) {
		replayCalls.Add(1)
		return replayResult{status: http.StatusOK}, nil
	})
	port := freeAllowedOAuthPort(t)
	b.SetCustodyConsumer(func(_ int, u *url.URL) bool {
		return u.Query().Get("state") == "owned-state"
	})
	if !b.EnsureCallbackPort(port) {
		t.Fatal("custody listener did not open")
	}

	// Guest output cannot turn a custody-owned listener into a transparent
	// one or install attacker-selected expectations on it.
	w := b.SniffWriter(io.Discard)
	printed := fmt.Sprintf("open http://localhost:%d/auth/callback?state=attacker-state\n", port)
	if _, err := w.Write([]byte(printed)); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	l := b.listeners[port]
	b.mu.Unlock()
	if l == nil || !l.custody || l.expectedPath != "" || l.expectedState != "" {
		t.Fatalf("custody listener was poisoned by sniffed output: %+v", l)
	}

	unknown := httptest.NewRecorder()
	b.handleCallback(l)(unknown, httptest.NewRequest(http.MethodGet, "/auth/callback?code=victim-code&state=victim-state", nil))
	if unknown.Code != http.StatusNotFound || replayCalls.Load() != 0 {
		t.Fatalf("unknown custody callback status/replays = %d/%d", unknown.Code, replayCalls.Load())
	}

	owned := httptest.NewRecorder()
	b.handleCallback(l)(owned, httptest.NewRequest(http.MethodGet, "/auth/callback?code=ours&state=owned-state", nil))
	if owned.Code != http.StatusOK || replayCalls.Load() != 0 || !strings.Contains(owned.Body.String(), "OAuth callback received") {
		t.Fatalf("owned custody callback status/replays/body = %d/%d/%q", owned.Code, replayCalls.Load(), owned.Body.String())
	}
	assertSafeBrowserHeaders(t, owned.Header())
	b.mu.Lock()
	stillActive := b.listeners[port] == l
	b.mu.Unlock()
	if !stillActive {
		t.Fatal("one custody callback closed a listener shared by pending flows")
	}
}

func TestCustodyRegistrationRefreshesListenerLifetime(t *testing.T) {
	b := testBridge(t, nil)
	port := freeAllowedOAuthPort(t)
	if !b.EnsureCallbackPort(port) {
		t.Fatal("first custody registration failed")
	}
	b.mu.Lock()
	l := b.listeners[port]
	firstGeneration := l.ttlGeneration
	b.mu.Unlock()
	if !b.EnsureCallbackPort(port) {
		t.Fatal("second custody registration failed")
	}
	b.mu.Lock()
	secondGeneration := l.ttlGeneration
	b.mu.Unlock()
	if secondGeneration <= firstGeneration {
		t.Fatalf("listener lifetime generation did not advance: %d -> %d", firstGeneration, secondGeneration)
	}

	// A callback from the retired timer cannot close the refreshed listener.
	b.closeExpiredListener(l, firstGeneration)
	b.mu.Lock()
	stillActive := b.listeners[port] == l
	b.mu.Unlock()
	if !stillActive {
		t.Fatal("retired custody TTL closed refreshed listener")
	}
}

func TestCustodyDoesNotReuseTransparentListener(t *testing.T) {
	b := testBridge(t, nil)
	port := freeAllowedOAuthPort(t)
	if !b.ensureListenerTarget(callbackTarget{port: port, path: "/callback", state: "transparent", validateState: true}) {
		t.Fatal("transparent listener did not open")
	}
	if b.EnsureCallbackPort(port) {
		t.Fatal("custody reused a transparent listener")
	}
}

func TestEnsureCallbackPortReportsBindFailure(t *testing.T) {
	b := testBridge(t, nil)
	port := freeAllowedOAuthPort(t)
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if b.EnsureCallbackPort(port) {
		t.Fatal("EnsureCallbackPort reported success when the host port was busy")
	}
	if b.EnsureCallbackPort(3000) {
		t.Fatal("EnsureCallbackPort accepted a disallowed port")
	}
}

func TestNewDefaultsOnWithExplicitOverrides(t *testing.T) {
	exec := func([]string, time.Duration) ([]byte, int, error) { return nil, 0, nil }
	t.Setenv("GANTRY_OAUTH_BRIDGE", "")
	if New(exec, true) == nil {
		t.Fatal("bridge must be built when the sandbox setting enables it")
	}
	if New(exec, false) != nil {
		t.Fatal("persisted oauth_bridge=false did not disable bridge")
	}
	t.Setenv("GANTRY_OAUTH_BRIDGE", "1")
	if New(exec, false) == nil {
		t.Fatal("GANTRY_OAUTH_BRIDGE=1 must override a persisted opt-out")
	}
	t.Setenv("GANTRY_OAUTH_BRIDGE", "0")
	if New(exec, true) != nil {
		t.Fatal("GANTRY_OAUTH_BRIDGE=0 must override default activation")
	}
	if New(nil, true) != nil {
		t.Fatal("a bridge without a guest exec must not be built")
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
