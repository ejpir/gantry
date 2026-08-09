package sandbox

// oauth_bridge.go — transparent OAuth loopback callback bridge.
//
// Agent CLIs (codex, claude, pi, …) sign in with an OAuth authorization-code
// flow against a loopback listener INSIDE the sandbox (codex:
// http://localhost:1455/auth/callback, pi: http://localhost:53692/callback,
// claude: http://localhost:<random>/callback). The CLI prints the authorize
// URL and waits for the provider to redirect the browser to the loopback
// listener — but the browser runs on the HOST, where that port is not the
// sandbox listener. The redirect dies in the host's network stack and login
// never completes.
//
// The daemon already relays every exec session's stdout through the broker,
// so it sees the printed authorize URL. This bridge:
//
//  1. sniffs session output for OAuth loopback redirect URLs
//     (redirect_uri=…localhost:<port>…, or a bare
//     http://localhost:<port>/callback-style URL);
//  2. binds 127.0.0.1:<port> on the host (loopback only, never LAN);
//  3. when the host browser lands on it, replays the callback into the
//     sandbox with an internal exec running a bash /dev/tcp one-shot —
//     no helper binary, no image/rootfs changes, no MITM, no new egress:
//     the request is made by a process inside the guest netns, which is
//     exactly what the CLI's loopback listener expects;
//  4. relays the CLI's HTTP response (its "sign-in complete" page) back
//     to the browser and closes the listener once a callback carrying
//     code=/error= has been delivered.
//
// Security posture: host listener binds 127.0.0.1 only; only GET requests
// are replayed; only the request path+query crosses the boundary (never
// browser headers/cookies); the replay target is guest loopback. A guest
// that prints fake URLs can only cause binds of host loopback ports it
// could already reach from inside the sandbox. Disable with
// GANTRY_OAUTH_BRIDGE=0.
//
// This mirrors the reference sandbox stack's behavior (host-side callback
// listener + replay via in-sandbox exec) without its TLS-intercepting
// proxy.

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/client"
)

// oauthBridge owns the host-side listeners for one sandbox daemon.
type oauthBridge struct {
	br *broker
	// replay executes one HTTP GET against guest loopback and returns the
	// raw response; a field so tests can substitute a local fake guest.
	replay func(port int, requestURI string) (status int, body []byte, err error)
	// logf defaults to the daemon log; tests capture it.
	logf func(format string, a ...any)

	mu        sync.Mutex
	listeners map[int]*oauthListener // port -> active host listener
	failed    map[int]bool           // ports we could not bind (stop retrying)
}

// oauthListener is one bound host port.
type oauthListener struct {
	port int
	ln   net.Listener
	done chan struct{}
}

var (
	// reOAuthRedirectURI matches the redirect_uri query parameter of a
	// printed authorize URL, URL-encoded or not:
	//   redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback
	//   redirect_uri=http://localhost:53692/callback
	reOAuthRedirectURI = regexp.MustCompile(`redirect_uri=([^&\s"'\)]+)`)
	// reOAuthLoopbackURL matches a directly printed callback URL:
	//   http://localhost:53692/callback  http://127.0.0.1:1455/auth/callback
	reOAuthLoopbackURL = regexp.MustCompile(`http://(?:localhost|127\.0\.0\.1):(\d{1,5})/[^\s"'\)]*callback`)
)

// newOAuthBridge creates the bridge for a broker, or nil when disabled via
// GANTRY_OAUTH_BRIDGE=0/false/no/off.
func newOAuthBridge(br *broker) *oauthBridge {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GANTRY_OAUTH_BRIDGE"))) {
	case "0", "false", "no", "off":
		return nil
	}
	return &oauthBridge{
		br:        br,
		logf:      func(format string, a ...any) { fmt.Printf("daemon: oauth bridge: "+format+"\n", a...) },
		listeners: map[int]*oauthListener{},
		failed:    map[int]bool{},
	}
}

// oauthCallbackPorts extracts host-side ports of OAuth loopback redirect
// targets from CLI output. It is the pure scanner core, kept separate for
// tests.
func oauthCallbackPorts(text string) []int {
	seen := map[int]bool{}
	add := func(p int) {
		if p > 1024 && p < 65536 { // skip privileged + invalid
			seen[p] = true
		}
	}
	for _, m := range reOAuthRedirectURI.FindAllStringSubmatch(text, -1) {
		raw, err := url.QueryUnescape(m[1])
		if err != nil {
			raw = m[1]
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "http" {
			continue
		}
		if h := u.Hostname(); h != "localhost" && h != "127.0.0.1" {
			continue
		}
		if p, err := strconv.Atoi(u.Port()); err == nil {
			add(p)
		}
	}
	for _, m := range reOAuthLoopbackURL.FindAllStringSubmatch(text, -1) {
		if p, err := strconv.Atoi(m[1]); err == nil {
			add(p)
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	return out
}

// sniffWriter returns a writer that forwards every byte unchanged while
// scanning for OAuth callback URLs. Safe for terminal byte streams: the
// scan is read-only over a rolling window.
func (b *oauthBridge) sniffWriter(w io.Writer) io.Writer {
	return &oauthSniffWriter{w: w, b: b}
}

type oauthSniffWriter struct {
	w   io.Writer
	b   *oauthBridge
	buf []byte // rolling tail window for URLs split across writes
}

func (s *oauthSniffWriter) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if n > 0 {
		s.buf = append(s.buf, p[:n]...)
		if len(s.buf) > 16384 {
			s.buf = s.buf[len(s.buf)-16384:]
		}
		for _, port := range oauthCallbackPorts(string(s.buf)) {
			s.b.ensureListener(port)
		}
	}
	return n, err
}

// ensureListener binds 127.0.0.1:port on the host once. Bind failures are
// remembered so repeated prints of the same URL don't spam.
func (b *oauthBridge) ensureListener(port int) {
	b.mu.Lock()
	if _, ok := b.listeners[port]; ok || b.failed[port] {
		b.mu.Unlock()
		return
	}
	b.mu.Unlock()

	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		b.mu.Lock()
		b.failed[port] = true
		b.mu.Unlock()
		b.logf("cannot bind host 127.0.0.1:%d (%v) — is something already using it?", port, err)
		return
	}
	l := &oauthListener{port: port, ln: ln, done: make(chan struct{})}
	b.mu.Lock()
	b.listeners[port] = l
	b.mu.Unlock()
	b.logf("OAuth callback detected: listening on host http://127.0.0.1:%d (replaying into the sandbox)", port)
	go b.serve(l)
}

// serve accepts browser connections until the listener closes.
func (b *oauthBridge) serve(l *oauthListener) {
	srv := &http.Server{
		Handler:           http.HandlerFunc(b.handleCallback(l)),
		ReadHeaderTimeout: 10 * time.Second,
	}
	// Idle safety: a flow the user abandons (never redirects) must not hold
	// the host port forever. Ten minutes matches common OAuth timeouts.
	time.AfterFunc(10*time.Minute, func() { b.closeListener(l.port) })
	_ = srv.Serve(l.ln)
}

// closeListener unbinds and forgets a port. Safe to call repeatedly.
func (b *oauthBridge) closeListener(port int) {
	b.mu.Lock()
	l, ok := b.listeners[port]
	delete(b.listeners, port)
	b.mu.Unlock()
	if ok {
		_ = l.ln.Close()
		b.logf("closed host listener on 127.0.0.1:%d", port)
	}
}

// handleCallback serves one browser request: replay the path+query into the
// sandbox's loopback listener and relay the response. After a request
// carrying the OAuth result (code=/error=) completes, the flow is done and
// the listener closes.
func (b *oauthBridge) handleCallback(l *oauthListener) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "gantry oauth bridge: only GET callbacks are replayed", http.StatusMethodNotAllowed)
			return
		}
		uri := r.URL.RequestURI()
		if len(uri) > 8192 {
			http.Error(w, "gantry oauth bridge: callback URL too long", http.StatusRequestURITooLong)
			return
		}
		status, body, err := b.replayIntoGuest(l.port, uri)
		if err != nil {
			b.logf("replay into sandbox failed (port %d): %v", l.port, err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprintf(w, `<html><body style="font-family:sans-serif;max-width:40em;margin:3em auto">`+
				`<h2>Sign-in could not be completed</h2><p>Gantry could not deliver the OAuth callback `+
				`to the CLI inside the sandbox: %s</p><p>Check that the CLI is still waiting for sign-in, `+
				`then retry. Details are in the sandbox daemon log.</p></body></html>`, err)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(body)
		if q := r.URL.Query(); q.Get("code") != "" || q.Get("error") != "" {
			// OAuth flows are one-shot: the CLI exchanges the code and
			// shuts its listener. Free the host port for the next login.
			time.AfterFunc(2*time.Second, func() { b.closeListener(l.port) })
		}
	}
}

// replayIntoGuest performs the callback GET inside the sandbox through the
// configured replay function (the real one execs bash /dev/tcp).
func (b *oauthBridge) replayIntoGuest(port int, requestURI string) (int, []byte, error) {
	if b.replay != nil {
		return b.replay(port, requestURI)
	}
	return b.replayViaDevTCP(port, requestURI)
}

// devTCPReplayScript is run inside the sandbox with: bash -c script -- PORT URI
// It opens a TCP connection to the CLI's loopback listener via bash's
// /dev/tcp, writes one HTTP/1.0 GET, and prints the raw response to stdout.
// bash is present in every gantry image (the default shell); containers
// share the VM netns, so 127.0.0.1 here is the CLI's listener.
const devTCPReplayScript = `set -u
port=$1; uri=$2
exec 3<>"/dev/tcp/127.0.0.1/$port" || { echo "oauth-replay: cannot connect to 127.0.0.1:$port (CLI not listening?)" >&2; exit 97; }
printf 'GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\nUser-Agent: gantry-oauth-bridge\r\nAccept: */*\r\nConnection: close\r\n\r\n' "$uri" >&3 || { echo "oauth-replay: write failed" >&2; exit 98; }
cat <&3
`

// replayViaDevTCP execs the replay script in the sandbox container and
// parses the CLI listener's raw HTTP response.
func (b *oauthBridge) replayViaDevTCP(port int, requestURI string) (int, []byte, error) {
	stdout, status, err := b.br.oauthExec([]string{"bash", "-c", devTCPReplayScript, "--", strconv.Itoa(port), requestURI})
	if err != nil {
		return 0, nil, fmt.Errorf("in-sandbox replay exec: %w", err)
	}
	if status != 0 {
		return 0, nil, fmt.Errorf("in-sandbox replay exited %d: %s", status, strings.TrimSpace(string(tailBytes(stdout, 512))))
	}
	// sessionExec appends a "client: exec exited, status N" trailer to
	// stdout (it is not Quiet-gated); strip it so it can never corrupt
	// close-delimited response bodies.
	stdout = bytes.TrimRight(stdout, "\n")
	if i := bytes.LastIndex(stdout, []byte("\nclient: exec exited, status ")); i >= 0 {
		stdout = stdout[:i+1]
	}
	return parseRawHTTPResponse(stdout)
}

// parseRawHTTPResponse splits a raw HTTP/1.x response (as printed by cat)
// into status code and body. A trailing "client: exec exited" line from
// the session layer is tolerated: Content-Length bodies are sliced exactly;
// close-delimited bodies keep the trailer harmlessly at the end.
func parseRawHTTPResponse(raw []byte) (int, []byte, error) {
	head, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		return 0, nil, fmt.Errorf("no HTTP response from the in-sandbox listener: %.200s", raw)
	}
	statusLine, headers, _ := bytes.Cut(head, []byte("\r\n"))
	fields := bytes.Fields(statusLine)
	if len(fields) < 2 || !bytes.HasPrefix(fields[0], []byte("HTTP/")) {
		return 0, nil, fmt.Errorf("malformed HTTP status line: %.100s", statusLine)
	}
	status, err := strconv.Atoi(string(fields[1]))
	if err != nil {
		return 0, nil, fmt.Errorf("malformed HTTP status code: %.100s", statusLine)
	}
	var chunked bool
	for _, line := range bytes.Split(headers, []byte("\r\n")) {
		k, v, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		switch {
		case bytes.EqualFold(bytes.TrimSpace(k), []byte("Content-Length")):
			if n, err := strconv.Atoi(string(bytes.TrimSpace(v))); err == nil && n >= 0 && n <= len(body) {
				body = body[:n]
			}
		case bytes.EqualFold(bytes.TrimSpace(k), []byte("Transfer-Encoding")):
			chunked = bytes.Contains(bytes.ToLower(v), []byte("chunked"))
		}
	}
	if chunked {
		if decoded, err := decodeChunkedBody(body); err == nil {
			body = decoded
		}
	}
	return status, body, nil
}

// decodeChunkedBody unfolds a Transfer-Encoding: chunked body. CLI OAuth
// listeners are Node (claude, pi) or Rust (codex) one-shots; Node answers
// without Content-Length use chunked framing, which must not leak chunk
// markers into the page relayed to the browser.
func decodeChunkedBody(raw []byte) ([]byte, error) {
	var out []byte
	rest := raw
	for {
		line, tail, ok := bytes.Cut(rest, []byte("\r\n"))
		if !ok {
			return nil, fmt.Errorf("truncated chunk header")
		}
		// Chunk sizes are hex, optionally followed by ;extensions.
		sizeText, _, _ := bytes.Cut(line, []byte(";"))
		n, err := strconv.ParseInt(strings.TrimSpace(string(sizeText)), 16, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("bad chunk size %q", line)
		}
		if n == 0 {
			return out, nil // last-chunk; trailers ignored
		}
		if int64(len(tail)) < n+2 {
			return nil, fmt.Errorf("truncated chunk data")
		}
		out = append(out, tail[:n]...)
		rest = tail[n+2:] // skip data + CRLF
	}
}

// tailBytes returns the last n bytes of b (for error messages).
func tailBytes(b []byte, n int) []byte {
	if len(b) > n {
		return b[len(b)-n:]
	}
	return b
}

// oauthExec runs a one-shot command inside the sandbox container and
// captures its stdout. It is a normal session exec, multiplexed over the
// daemon's single guest RPC connection like any concurrent `gantry exec`.
// User secrets are deliberately NOT injected into this internal process.
func (br *broker) oauthExec(args []string) ([]byte, int, error) {
	var buf bytes.Buffer
	var status int
	manifest := client.LoadShareManifest(br.dir)
	err := client.Session(br.rpc, client.SessionOptions{
		StreamSock:       br.streamSock,
		StreamDial:       br.streamDial,
		Shares:           manifest.Shares,
		ShareTransport:   manifest.Transport,
		RW:               br.cfg.RW,
		LayerSet:         br.cfg.LayerSet,
		Args:             args,
		ID:               "sb",
		ExecIntoExisting: true,
		ImgCfg:           br.cfg.ImageCfg,
		Quiet:            true,
		ExitStatus:       &status,
	}, strings.NewReader(""), &buf)
	return buf.Bytes(), status, err
}
