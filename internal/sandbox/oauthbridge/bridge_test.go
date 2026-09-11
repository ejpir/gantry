package oauthbridge

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

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
		listeners := make([]*listener, 0, len(b.listeners))
		for _, l := range b.listeners {
			listeners = append(listeners, l)
		}
		b.mu.Unlock()
		for _, l := range listeners {
			b.closeExactListener(l)
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

func TestAllowedCallbackPorts(t *testing.T) {
	for _, port := range []int{1455, 32768, 53692, 65535} {
		if !allowedCallbackPort(port) {
			t.Errorf("port %d was rejected", port)
		}
	}
	for _, port := range []int{0, 3000, 32767, 65536} {
		if allowedCallbackPort(port) {
			t.Errorf("port %d was accepted", port)
		}
	}
}

func TestBridgeEndToEndFromDiscoveredListener(t *testing.T) {
	var gotURI string
	guest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI = r.URL.RequestURI()
		_, _ = fmt.Fprint(w, "<html>guest response</html>")
	}))
	defer guest.Close()

	b := testBridge(t, func(_ int, uri string) (replayResult, error) {
		resp, err := http.Get(guest.URL + uri)
		if err != nil {
			return replayResult{}, err
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return replayResult{status: resp.StatusCode}, nil
	})
	port := freeAllowedOAuthPort(t)
	if !b.OpenGuestListener(port) {
		t.Fatal("discovered guest listener did not open a host callback gate")
	}

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/?code=abc123&state=opaque", port))
	if err != nil {
		t.Fatalf("browser callback: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "OAuth callback delivered") {
		t.Fatalf("response = %d %q", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "guest response") {
		t.Fatalf("guest-controlled response reached browser: %s", body)
	}
	if gotURI != "/?code=abc123&state=opaque" {
		t.Fatalf("guest saw URI %q", gotURI)
	}
	assertSafeBrowserHeaders(t, resp.Header)
}

func TestTransparentGateAcceptsOnlyOAuthResults(t *testing.T) {
	var calls atomic.Int32
	b := testBridge(t, func(_ int, _ string) (replayResult, error) {
		calls.Add(1)
		return replayResult{status: http.StatusOK}, nil
	})
	l := &listener{port: 55123}
	for _, uri := range []string{
		"/health",
		"/?state=only-state",
		"/?code=only-code",
		"/?error=access_denied",
	} {
		rec := httptest.NewRecorder()
		b.handleCallback(l)(rec, httptest.NewRequest(http.MethodGet, uri, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", uri, rec.Code)
		}
	}
	for _, uri := range []string{
		"/any/path?code=x&state=s",
		"/?error=access_denied&state=s",
	} {
		rec := httptest.NewRecorder()
		b.handleCallback(l)(rec, httptest.NewRequest(http.MethodGet, uri, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", uri, rec.Code)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("replay calls = %d, want 2", calls.Load())
	}
}

func TestBridgeDoesNotForwardGuestRedirectOrMetadata(t *testing.T) {
	b := testBridge(t, func(_ int, _ string) (replayResult, error) {
		raw := "HTTP/1.1 302 Found\r\n" +
			"Content-Type: application/javascript\r\n" +
			"Location: https://attacker.example/from-guest\r\n\r\n" +
			`<script>fetch("http://127.0.0.1:2375/attack")</script>`
		return parseRawHTTPResponse([]byte(raw))
	})
	rec := httptest.NewRecorder()
	b.handleCallback(&listener{port: 1})(rec, httptest.NewRequest(http.MethodGet, "/?code=x&state=s", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Location") != "" || strings.Contains(rec.Body.String(), "script") {
		t.Fatalf("guest metadata reached browser: headers=%v body=%s", rec.Header(), rec.Body.String())
	}
	assertSafeBrowserHeaders(t, rec.Header())
}

func TestCustodyListenerFailsClosed(t *testing.T) {
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
	b.mu.Lock()
	l := b.listeners[port]
	b.mu.Unlock()

	unknown := httptest.NewRecorder()
	b.handleCallback(l)(unknown, httptest.NewRequest(http.MethodGet, "/?code=victim&state=other", nil))
	if unknown.Code != http.StatusNotFound || replayCalls.Load() != 0 {
		t.Fatalf("unknown custody callback status/replays = %d/%d", unknown.Code, replayCalls.Load())
	}
	owned := httptest.NewRecorder()
	b.handleCallback(l)(owned, httptest.NewRequest(http.MethodGet, "/?code=ours&state=owned-state", nil))
	if owned.Code != http.StatusOK || replayCalls.Load() != 0 || !strings.Contains(owned.Body.String(), "OAuth callback received") {
		t.Fatalf("owned custody callback status/replays/body = %d/%d/%q", owned.Code, replayCalls.Load(), owned.Body.String())
	}
}

func TestDiscoveredAndCustodyListenersCannotReplaceEachOther(t *testing.T) {
	b := testBridge(t, nil)
	transparentPort := freeAllowedOAuthPort(t)
	if !b.OpenGuestListener(transparentPort) {
		t.Fatal("transparent listener did not open")
	}
	if b.EnsureCallbackPort(transparentPort) {
		t.Fatal("custody reused a transparent listener")
	}

	custodyPort := transparentPort + 1
	for {
		probe, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", custodyPort))
		if err == nil {
			_ = probe.Close()
			break
		}
		custodyPort++
	}
	if !b.EnsureCallbackPort(custodyPort) {
		t.Fatal("custody listener did not open")
	}
	if b.OpenGuestListener(custodyPort) {
		t.Fatal("transparent discovery reused a custody listener")
	}
}

func TestCloseGuestListenerClearsFailureForRetry(t *testing.T) {
	b := testBridge(t, nil)
	port := freeAllowedOAuthPort(t)
	occupied, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	if b.OpenGuestListener(port) {
		t.Fatal("bridge bound an occupied host port")
	}
	b.CloseGuestListener(port)
	_ = occupied.Close()
	if !b.OpenGuestListener(port) {
		t.Fatal("fresh guest bind did not retry a previous host bind failure")
	}
}

func TestCloseGuestListenersPreservesCustody(t *testing.T) {
	b := testBridge(t, nil)
	transparentPort := freeAllowedOAuthPort(t)
	if !b.OpenGuestListener(transparentPort) {
		t.Fatal("transparent listener did not open")
	}
	custodyPort := transparentPort + 1
	for !b.EnsureCallbackPort(custodyPort) {
		custodyPort++
		if custodyPort > 65535 {
			t.Fatal("no free custody port")
		}
	}
	b.CloseGuestListeners()
	b.mu.Lock()
	_, transparentActive := b.listeners[transparentPort]
	custody := b.listeners[custodyPort]
	b.mu.Unlock()
	if transparentActive || custody == nil || !custody.custody {
		t.Fatalf("listeners after watcher close: transparent=%v custody=%+v", transparentActive, custody)
	}
}

func TestBridgeListenerLimit(t *testing.T) {
	b := testBridge(t, nil)
	for i := 0; i < maxActiveListeners; i++ {
		port := 55000 + i
		b.listeners[port] = &listener{port: port, ln: closedTestListener{}}
	}
	target := 56000
	if b.OpenGuestListener(target) {
		t.Fatal("listener opened beyond limit")
	}
	b.mu.Lock()
	_, added := b.listeners[target]
	b.listeners = map[int]*listener{}
	b.mu.Unlock()
	if added {
		t.Fatal("overflow listener was retained")
	}
}

type closedTestListener struct{}

func (closedTestListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (closedTestListener) Close() error              { return nil }
func (closedTestListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestBridgeRejectsNonGETAndOversizeURI(t *testing.T) {
	b := testBridge(t, func(int, string) (replayResult, error) {
		t.Fatal("invalid request must not be replayed")
		return replayResult{}, nil
	})
	l := &listener{port: 1}
	post := httptest.NewRecorder()
	b.handleCallback(l)(post, httptest.NewRequest(http.MethodPost, "/?code=x&state=s", nil))
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", post.Code)
	}
	oversize := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/?code=x&state="+strings.Repeat("x", maxRequestURIBytes), nil)
	b.handleCallback(l)(oversize, request)
	if oversize.Code != http.StatusRequestURITooLong {
		t.Fatalf("oversize status = %d", oversize.Code)
	}
}

func TestBridgeCapsConcurrentReplays(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, maxConcurrentReplays)
	b := testBridge(t, func(int, string) (replayResult, error) {
		started <- struct{}{}
		<-release
		return replayResult{status: http.StatusOK}, nil
	})
	l := &listener{port: 1455}
	done := make(chan struct{}, maxConcurrentReplays)
	for i := 0; i < maxConcurrentReplays; i++ {
		go func(i int) {
			rec := httptest.NewRecorder()
			b.handleCallback(l)(rec, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/?code=%d&state=s", i), nil))
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
	overflow := httptest.NewRecorder()
	b.handleCallback(l)(overflow, httptest.NewRequest(http.MethodGet, "/?code=overflow&state=s", nil))
	if overflow.Code != http.StatusTooManyRequests {
		t.Fatalf("overflow status = %d", overflow.Code)
	}
	close(release)
	for i := 0; i < maxConcurrentReplays; i++ {
		<-done
	}
}

func TestBridgeReplayTimeoutKeepsSlotCharged(t *testing.T) {
	release := make(chan struct{})
	b := testBridge(t, func(int, string) (replayResult, error) {
		<-release
		return replayResult{status: http.StatusOK}, nil
	})
	b.replayTimeout = 20 * time.Millisecond
	rec := httptest.NewRecorder()
	b.handleCallback(&listener{port: 1})(rec, httptest.NewRequest(http.MethodGet, "/?code=x&state=s", nil))
	if rec.Code != http.StatusGatewayTimeout || len(b.replaySlots) != 1 {
		t.Fatalf("timeout status/slots = %d/%d", rec.Code, len(b.replaySlots))
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for len(b.replaySlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(b.replaySlots) != 0 {
		t.Fatal("replay slot was not released")
	}
}

func TestBridgeReplayFailureReturnsSafeBadGateway(t *testing.T) {
	b := testBridge(t, func(int, string) (replayResult, error) {
		return replayResult{}, fmt.Errorf(`<script>attack()</script>`)
	})
	rec := httptest.NewRecorder()
	b.handleCallback(&listener{port: 1})(rec, httptest.NewRequest(http.MethodGet, "/?code=x&state=s", nil))
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "could not deliver") || strings.Contains(rec.Body.String(), "script") {
		t.Fatalf("unsafe failure response: %d %q", rec.Code, rec.Body.String())
	}
}

func assertSafeBrowserHeaders(t *testing.T, header http.Header) {
	t.Helper()
	if csp := header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "sandbox") {
		t.Fatalf("unsafe or missing CSP: %q", csp)
	}
	if header.Get("X-Content-Type-Options") != "nosniff" || header.Get("Cache-Control") != "no-store" {
		t.Fatalf("missing browser security headers: %v", header)
	}
	if got := header.Get("Clear-Site-Data"); got != `"cache", "storage"` {
		t.Fatalf("Clear-Site-Data = %q", got)
	}
}

func TestReplayViaDevTCPPreservesEmptyRedirectTerminator(t *testing.T) {
	response := "HTTP/1.0 302 Found\r\nLocation: http://localhost/success\r\n\r\n"
	for _, suffix := range []string{"", "\nclient: task exited, status 0\n"} {
		b := &Bridge{exec: func([]string, time.Duration) ([]byte, int, error) {
			return []byte(response + suffix), 0, nil
		}}
		res, err := b.replayViaDevTCP(1455, "/?code=abc&state=s")
		if err != nil || res.status != http.StatusFound {
			t.Fatalf("suffix %q: response=%+v err=%v", suffix, res, err)
		}
	}
}

func TestParseRawHTTPResponse(t *testing.T) {
	for _, raw := range []string{
		"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 302 Found\nLocation: https://example.invalid\n\n",
	} {
		if _, err := parseRawHTTPResponse([]byte(raw)); err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
	}
	for _, raw := range [][]byte{
		[]byte("garbage"),
		[]byte("oops\r\n\r\nbody"),
		[]byte(strings.Repeat("x", MaxReplayResponseSize+1)),
	} {
		if _, err := parseRawHTTPResponse(raw); err == nil {
			t.Fatalf("accepted malformed response prefix %.20q", raw)
		}
	}
}

func TestNewDefaultsOnWithExplicitOverrides(t *testing.T) {
	exec := func([]string, time.Duration) ([]byte, int, error) { return nil, 0, nil }
	t.Setenv("GANTRY_OAUTH_BRIDGE", "")
	if New(exec, true) == nil || New(exec, false) != nil {
		t.Fatal("persisted OAuth bridge setting was not respected")
	}
	t.Setenv("GANTRY_OAUTH_BRIDGE", "1")
	if New(exec, false) == nil {
		t.Fatal("global enable override was ignored")
	}
	t.Setenv("GANTRY_OAUTH_BRIDGE", "0")
	if New(exec, true) != nil {
		t.Fatal("global disable override was ignored")
	}
	if New(nil, true) != nil {
		t.Fatal("bridge without guest exec was created")
	}
}

func TestDevTCPReplayScriptShape(t *testing.T) {
	if !strings.Contains(devTCPReplayScript, `/dev/tcp/localhost/$port`) {
		t.Fatal("script must target guest loopback only")
	}
	if strings.Contains(devTCPReplayScript, "curl") || strings.Contains(devTCPReplayScript, "wget") {
		t.Fatal("script must not depend on external HTTP tools")
	}
	if !strings.Contains(devTCPReplayScript, "printf 'GET %s HTTP/1.0") {
		t.Fatal("script must issue exactly one GET")
	}
}
