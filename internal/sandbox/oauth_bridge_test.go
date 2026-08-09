package sandbox

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
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
	// A bare http://localhost:PORT/<non-callback> URL must not arm the
	// bridge: only redirect_uri params or *callback* paths count.
	if got := oauthCallbackPorts("curl http://localhost:3000/health && break"); len(got) != 0 {
		t.Fatalf("ports = %v, want none", got)
	}
}

func testBridge(t *testing.T, replay func(port int, uri string) (int, []byte, error)) *oauthBridge {
	t.Helper()
	b := &oauthBridge{
		replay:    replay,
		logf:      func(string, ...any) {},
		listeners: map[int]*oauthListener{},
		failed:    map[int]bool{},
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

	b := testBridge(t, func(port int, uri string) (int, []byte, error) {
		resp, err := http.Get(guest.URL + uri)
		if err != nil {
			return 0, nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		return resp.StatusCode, body, err
	})

	// Sniff a codex-style authorize URL; the bridge must bind 1455-equivalent.
	// Use a free port instead of 1455 to avoid host collisions in CI.
	freeLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := freeLn.Addr().(*net.TCPAddr).Port
	_ = freeLn.Close()

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

func TestBridgeReplayFailureReturnsBadGateway(t *testing.T) {
	b := testBridge(t, func(port int, uri string) (int, []byte, error) {
		return 0, nil, fmt.Errorf("in-sandbox replay exited 97: cannot connect")
	})
	l := &oauthListener{port: 1, done: make(chan struct{})}
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
	b := testBridge(t, func(port int, uri string) (int, []byte, error) {
		t.Fatal("replay must not run for POST")
		return 0, nil, nil
	})
	l := &oauthListener{port: 1, done: make(chan struct{})}
	req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader("x"))
	rec := httptest.NewRecorder()
	b.handleCallback(l)(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestParseRawHTTPResponse(t *testing.T) {
	raw := "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, world!\nclient: exec exited, status 0\n"
	status, body, err := parseRawHTTPResponse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if status != 200 {
		t.Fatalf("status = %d", status)
	}
	if string(body) != "Hello, world!" {
		t.Fatalf("body = %q (session trailer leaked into Content-Length body)", body)
	}

	// Close-delimited body without Content-Length: trailer is stripped
	// by replayViaDevTCP; the parser sees it only if it leaked.
	raw2 := "HTTP/1.0 302 Found\r\nLocation: /\r\n\r\nbye\n"
	status, body, err = parseRawHTTPResponse([]byte(raw2))
	if err != nil || status != 302 {
		t.Fatalf("status %d err %v", status, err)
	}
	if !strings.HasPrefix(string(body), "bye") {
		t.Fatalf("body = %q", body)
	}

	// Node-style chunked response (claude/pi listeners).
	raw3 := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"8\r\nSign-in \r\n8\r\ncomplete\r\n0\r\n\r\n"
	status, body, err = parseRawHTTPResponse([]byte(raw3))
	if err != nil || status != 200 {
		t.Fatalf("chunked: status %d err %v", status, err)
	}
	if string(body) != "Sign-in complete" {
		t.Fatalf("chunked body = %q", body)
	}

	if _, _, err := parseRawHTTPResponse([]byte("garbage")); err == nil {
		t.Fatal("expected error for non-HTTP input")
	}
	if _, _, err := parseRawHTTPResponse([]byte("oops\r\n\r\nbody")); err == nil {
		t.Fatal("expected error for malformed status line")
	}
}

func TestSniffWriterDedupesAndBindFailure(t *testing.T) {
	b := testBridge(t, nil)

	// Bind a port ourselves so the bridge's bind fails.
	freeLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = freeLn.Close() }()
	port := freeLn.Addr().(*net.TCPAddr).Port

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

func TestNewOAuthBridgeDisabled(t *testing.T) {
	t.Setenv("GANTRY_OAUTH_BRIDGE", "0")
	if newOAuthBridge(&broker{}) != nil {
		t.Fatal("bridge must be nil when GANTRY_OAUTH_BRIDGE=0")
	}
	t.Setenv("GANTRY_OAUTH_BRIDGE", "")
	if newOAuthBridge(&broker{}) == nil {
		t.Fatal("bridge must default to enabled")
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
