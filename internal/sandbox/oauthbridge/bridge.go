// Package oauthbridge runs the host-side OAuth loopback callback bridge for a
// sandbox. A CLI inside the guest prints an authorize URL whose redirect_uri
// points at guest loopback; the browser that opens it runs on the host, where
// that port means nothing. The bridge sniffs the printed URL, binds the same
// port on the host, and replays each callback request into the guest.
//
// It reaches the guest through a single injected Exec: one command run inside
// the sandbox container. That keeps the bridge independent of the daemon's
// broker, session limits and RPC plumbing, which own that call.
package oauthbridge

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
// Security posture: the bridge is enabled by default, with per-sandbox and
// global opt-outs. Host listeners bind 127.0.0.1 only and are restricted to
// the documented fixed callback ports or the dynamic OAuth range. Listener
// count, replay concurrency, duration, request size, and response size are all
// bounded. Only GET path+query is replayed to guest loopback; browser headers
// and cookies never cross the boundary.
//
// This mirrors the reference sandbox stack's behavior (host-side callback
// listener + replay via in-sandbox exec) without its TLS-intercepting
// proxy.

import (
	"bytes"
	"fmt"
	"html"
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
)

const (
	maxActiveListeners    = 4
	maxFailedPorts        = 64
	maxPortsPerSession    = 4
	maxConcurrentReplays  = 2
	maxRequestURIBytes    = 8 << 10
	MaxReplayResponseSize = 256 << 10
	ReplayTimeout         = 15 * time.Second
	listenerLifetime      = 10 * time.Minute
)

// Bridge owns the host-side listeners for one sandbox daemon.
// Exec runs one command inside the sandbox container and returns its captured
// stdout and exit status. The daemon supplies it; the bridge never learns how
// the guest is reached.
type Exec func(args []string, timeout time.Duration) ([]byte, int, error)

type Bridge struct {
	exec Exec
	// replay executes one HTTP GET against guest loopback and returns the
	// parsed response; a field so tests can substitute a local fake guest.
	replay func(port int, requestURI string) (replayResult, error)
	// logf defaults to the daemon log; tests capture it.
	logf func(format string, a ...any)

	mu        sync.Mutex
	listeners map[int]*listener // port -> active host listener
	failed    map[int]bool      // ports we could not bind (stop retrying)

	// replaySlots is a non-blocking semaphore. A full semaphore returns
	// 429 rather than accumulating browser-handler goroutines behind a
	// wedged guest callback listener.
	replaySlots chan struct{}
	// Tests shorten these; zero selects the production defaults.
	replayTimeout    time.Duration
	listenerLifetime time.Duration

	// custodyConsume, when set and returning true, intercepts a callback
	// for host-side token exchange (custody mode) instead of replaying
	// it into the guest.
	custodyConsume func(port int, u *url.URL) bool
}

// listener is one bound host port.
type listener struct {
	port int
	ln   net.Listener
	ttl  *time.Timer
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

// New creates the default-on, resource-bounded bridge. The persisted
// sandbox setting can opt out; GANTRY_OAUTH_BRIDGE is a global override.
// New creates the default-on, resource-bounded bridge. enabled is the
// persisted sandbox setting; GANTRY_OAUTH_BRIDGE is a global override. It
// returns nil when the bridge is switched off, which callers treat as "no
// bridge" rather than an error.
func New(exec Exec, enabled bool) *Bridge {
	if exec == nil {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GANTRY_OAUTH_BRIDGE"))) {
	case "1", "true", "yes", "on":
		enabled = true
	case "0", "false", "no", "off":
		return nil
	}
	if !enabled {
		return nil
	}
	return &Bridge{
		exec:             exec,
		logf:             func(format string, a ...any) { fmt.Printf("daemon: oauth bridge: "+format+"\n", a...) },
		listeners:        map[int]*listener{},
		failed:           map[int]bool{},
		replaySlots:      make(chan struct{}, maxConcurrentReplays),
		replayTimeout:    ReplayTimeout,
		listenerLifetime: listenerLifetime,
	}
}

// allowedCallbackPort keeps stdout-derived binds away from arbitrary
// host services. Codex and pi use the two fixed ports; Claude-style dynamic
// callbacks use the IANA dynamic/private range.
func allowedCallbackPort(port int) bool {
	return port == 1455 || port == 53692 || port >= 49152 && port <= 65535
}

// callbackPorts extracts host-side ports of OAuth loopback redirect
// targets from CLI output. It is the pure scanner core, kept separate for
// tests.
func callbackPorts(text string) []int {
	seen := map[int]bool{}
	add := func(p int) {
		if allowedCallbackPort(p) {
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
		if !strings.Contains(strings.ToLower(u.Path), "callback") {
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

// SniffWriter returns a writer that forwards every byte unchanged while
// SetCustodyConsumer installs the custody-mode interception hook: when
// non-nil and returning true, a callback is consumed host-side (daemon
// token exchange) and NOT replayed into the guest.
func (b *Bridge) SetCustodyConsumer(consume func(port int, u *url.URL) bool) {
	b.custodyConsume = consume
}

// EnsureCallbackPort opens the host loopback listener for a custody flow
// before any authorize URL has been sniffed (the guest helper declares
// its redirect port up front).
func (b *Bridge) EnsureCallbackPort(port int) {
	if allowedCallbackPort(port) {
		b.ensureListener(port)
	}
}

// scanning for OAuth callback URLs. Safe for terminal byte streams: the
// scan is read-only over a rolling window.
func (b *Bridge) SniffWriter(w io.Writer) io.Writer {
	return &sniffWriter{w: w, b: b, seen: map[int]bool{}}
}

type sniffWriter struct {
	w   io.Writer
	b   *Bridge
	buf []byte // rolling tail window for URLs split across writes
	// A declared session may arm a small number of flows, not walk the
	// entire dynamic port range by printing synthetic authorize URLs.
	seen map[int]bool
}

func (s *sniffWriter) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if n > 0 {
		s.buf = append(s.buf, p[:n]...)
		if len(s.buf) > 16384 {
			s.buf = s.buf[len(s.buf)-16384:]
		}
		for _, port := range callbackPorts(string(s.buf)) {
			if s.seen[port] || len(s.seen) >= maxPortsPerSession {
				continue
			}
			s.seen[port] = true
			s.b.ensureListener(port)
		}
	}
	return n, err
}

// ensureListener binds 127.0.0.1:port on the host once. Bind failures are
// remembered so repeated prints of the same URL don't spam.
func (b *Bridge) ensureListener(port int) {
	if !allowedCallbackPort(port) {
		return
	}
	b.mu.Lock()
	if _, ok := b.listeners[port]; ok || b.failed[port] {
		b.mu.Unlock()
		return
	}
	if len(b.listeners) >= maxActiveListeners {
		b.mu.Unlock()
		b.logf("listener limit reached (%d); ignoring callback port %d", maxActiveListeners, port)
		return
	}
	// Keep the lock across bind so concurrent output cannot race the same
	// port or exceed the listener limit between check and publication.
	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		if len(b.failed) >= maxFailedPorts {
			b.failed = map[int]bool{}
		}
		b.failed[port] = true
		b.mu.Unlock()
		b.logf("cannot bind host 127.0.0.1:%d (%v) — is something already using it?", port, err)
		return
	}
	l := &listener{port: port, ln: ln}
	// A flow the user abandons must not hold the host port forever.
	l.ttl = time.AfterFunc(b.lifetime(), func() { b.closeExactListener(l) })
	b.listeners[port] = l
	b.mu.Unlock()
	b.logf("OAuth callback detected: listening on host http://127.0.0.1:%d (replaying into the sandbox)", port)
	go b.serve(l)
}

// serve accepts browser connections until the listener closes.
func (b *Bridge) serve(l *listener) {
	replayTimeout := b.timeout()
	srv := &http.Server{
		Handler:           http.HandlerFunc(b.handleCallback(l)),
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      replayTimeout + 5*time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	_ = srv.Serve(l.ln)
	b.closeExactListener(l)
}

// closeListener unbinds and forgets a port. Safe to call repeatedly.
func (b *Bridge) closeListener(port int) {
	b.mu.Lock()
	l := b.listeners[port]
	b.mu.Unlock()
	if l != nil {
		b.closeExactListener(l)
	}
}

// closeExactListener prevents an old TTL/callback timer from closing a new
// listener that later reused the same port.
func (b *Bridge) closeExactListener(l *listener) {
	b.mu.Lock()
	if b.listeners[l.port] != l {
		b.mu.Unlock()
		return
	}
	// Close before making the port available for reuse. Otherwise a scanner
	// can observe the deleted map entry, race the still-open socket, and
	// permanently cache an EADDRINUSE failure for this bridge.
	if l.ttl != nil {
		l.ttl.Stop()
	}
	_ = l.ln.Close()
	delete(b.listeners, l.port)
	b.mu.Unlock()
	b.logf("closed host listener on 127.0.0.1:%d", l.port)
}

func (b *Bridge) timeout() time.Duration {
	if b.replayTimeout > 0 {
		return b.replayTimeout
	}
	return ReplayTimeout
}

func (b *Bridge) lifetime() time.Duration {
	if b.listenerLifetime > 0 {
		return b.listenerLifetime
	}
	return listenerLifetime
}

func (b *Bridge) acquireReplay() bool {
	select {
	case b.replaySlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (b *Bridge) releaseReplay() { <-b.replaySlots }

// handleCallback serves one browser request: replay the path+query into the
// sandbox's loopback listener and relay the response. After a request
// carrying the OAuth result (code=/error=) completes, the flow is done and
// the listener closes.
func (b *Bridge) handleCallback(l *listener) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "gantry oauth bridge: only GET callbacks are replayed", http.StatusMethodNotAllowed)
			return
		}
		uri := r.URL.RequestURI()
		if len(uri) > maxRequestURIBytes {
			http.Error(w, "gantry oauth bridge: callback URL too long", http.StatusRequestURITooLong)
			return
		}
		// Custody mode: the daemon completes the flow host-side. A
		// consumed callback is never replayed into the guest — the whole
		// point is that the authorization code (and the tokens it yields)
		// stay on the host.
		if b.custodyConsume != nil && b.custodyConsume(l.port, r.URL) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, "<html><body><h2>Login complete</h2><p>Gantry holds this session's tokens on the host (custody mode). You can close this tab.</p></body></html>")
			return
		}
		if !b.acquireReplay() {
			http.Error(w, "gantry oauth bridge: too many callbacks are already being replayed", http.StatusTooManyRequests)
			return
		}
		type outcome struct {
			res replayResult
			err error
		}
		done := make(chan outcome, 1)
		go func() {
			var out outcome
			defer func() {
				if recovered := recover(); recovered != nil {
					out = outcome{err: fmt.Errorf("callback replay panic: %v", recovered)}
				}
				done <- out
			}()
			out.res, out.err = b.replayIntoGuest(l.port, uri)
		}()
		timer := time.NewTimer(b.timeout())
		var out outcome
		select {
		case out = <-done:
			timer.Stop()
			b.releaseReplay()
		case <-timer.C:
			// Keep the slot charged until the underlying replay actually
			// unwinds. Even a guest/RPC bug that ignores cancellation can
			// therefore strand at most maxConcurrentReplays goroutines.
			go func() {
				<-done
				b.releaseReplay()
			}()
			http.Error(w, "gantry oauth bridge: callback replay timed out", http.StatusGatewayTimeout)
			return
		case <-r.Context().Done():
			timer.Stop()
			go func() {
				<-done
				b.releaseReplay()
			}()
			return
		}
		res, err := out.res, out.err
		if err != nil {
			b.logf("replay into sandbox failed (port %d): %v", l.port, err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprintf(w, `<html><body style="font-family:sans-serif;max-width:40em;margin:3em auto">`+
				`<h2>Sign-in could not be completed</h2><p>Gantry could not deliver the OAuth callback `+
				`to the CLI inside the sandbox: %s</p><p>Check that the CLI is still waiting for sign-in, `+
				`then retry. Details are in the sandbox daemon log.</p></body></html>`, html.EscapeString(err.Error()))
			return
		}
		if len(res.body) > MaxReplayResponseSize {
			b.logf("replay response from sandbox port %d exceeded %d bytes", l.port, MaxReplayResponseSize)
			http.Error(w, "gantry oauth bridge: callback response too large", http.StatusBadGateway)
			return
		}
		if res.status < 200 || res.status > 599 {
			b.logf("replay response from sandbox port %d used invalid status %d", l.port, res.status)
			http.Error(w, "gantry oauth bridge: invalid callback response", http.StatusBadGateway)
			return
		}
		ct := res.contentType
		if ct == "" {
			ct = "text/html; charset=utf-8"
		}
		w.Header().Set("Content-Type", ct)
		if res.location != "" {
			// Codex answers /auth/callback with a 302 to its result page;
			// the browser follows it back through this listener, which
			// replays the target into the guest like any other GET.
			w.Header().Set("Location", res.location)
		}
		w.WriteHeader(res.status)
		_, _ = w.Write(res.body)
		if q := r.URL.Query(); q.Get("code") != "" || q.Get("error") != "" {
			// OAuth flows are one-shot: the CLI exchanges the code and
			// shuts its listener. Free the host port for the next login.
			time.AfterFunc(2*time.Second, func() { b.closeExactListener(l) })
		}
	}
}

// replayResult is the guest listener's answer to a replayed
// callback. Location matters: CLIs like codex answer /auth/callback with
// a 302 to their success/error page, and a Location-less 302 renders as
// a blank browser page — the exact symptom seen in field testing.
type replayResult struct {
	status      int
	contentType string // guest Content-Type; the handler default applies when empty
	location    string // guest Location redirect target, forwarded verbatim
	body        []byte
}

// replayIntoGuest performs the callback GET inside the sandbox through the
// configured replay function (the real one execs bash /dev/tcp).
func (b *Bridge) replayIntoGuest(port int, requestURI string) (replayResult, error) {
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
func (b *Bridge) replayViaDevTCP(port int, requestURI string) (replayResult, error) {
	stdout, status, err := b.exec(
		[]string{"bash", "-c", devTCPReplayScript, "--", strconv.Itoa(port), requestURI},
		b.timeout(),
	)
	if err != nil {
		return replayResult{}, fmt.Errorf("in-sandbox replay exec: %w", err)
	}
	if status != 0 {
		return replayResult{}, fmt.Errorf("in-sandbox replay exited %d: %s", status, strings.TrimSpace(string(tailBytes(stdout, 512))))
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
// into status, the headers worth relaying (Content-Type, Location), and
// body. Content-Length bodies are sliced exactly; chunked bodies are
// unfolded.
func parseRawHTTPResponse(raw []byte) (replayResult, error) {
	if len(raw) > MaxReplayResponseSize {
		return replayResult{}, fmt.Errorf("HTTP response exceeds %d bytes", MaxReplayResponseSize)
	}
	head, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		return replayResult{}, fmt.Errorf("no HTTP response from the in-sandbox listener: %.200s", raw)
	}
	statusLine, headers, _ := bytes.Cut(head, []byte("\r\n"))
	fields := bytes.Fields(statusLine)
	if len(fields) < 2 || !bytes.HasPrefix(fields[0], []byte("HTTP/")) {
		return replayResult{}, fmt.Errorf("malformed HTTP status line: %.100s", statusLine)
	}
	status, err := strconv.Atoi(string(fields[1]))
	if err != nil {
		return replayResult{}, fmt.Errorf("malformed HTTP status code: %.100s", statusLine)
	}
	if status < 200 || status > 599 {
		return replayResult{}, fmt.Errorf("invalid HTTP status code %d", status)
	}
	res := replayResult{status: status, body: body}
	var chunked bool
	for _, line := range bytes.Split(headers, []byte("\r\n")) {
		k, v, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		v = bytes.TrimSpace(v)
		switch {
		case bytes.EqualFold(bytes.TrimSpace(k), []byte("Content-Length")):
			if n, err := strconv.Atoi(string(v)); err == nil && n >= 0 {
				if n > MaxReplayResponseSize {
					return replayResult{}, fmt.Errorf("HTTP response Content-Length %d exceeds %d bytes", n, MaxReplayResponseSize)
				}
				if n > len(res.body) {
					return replayResult{}, fmt.Errorf("truncated HTTP response body: got %d bytes, want %d", len(res.body), n)
				}
				res.body = res.body[:n]
			}
		case bytes.EqualFold(bytes.TrimSpace(k), []byte("Transfer-Encoding")):
			chunked = bytes.Contains(bytes.ToLower(v), []byte("chunked"))
		case bytes.EqualFold(bytes.TrimSpace(k), []byte("Content-Type")):
			res.contentType = string(v)
		case bytes.EqualFold(bytes.TrimSpace(k), []byte("Location")):
			res.location = string(v)
		}
	}
	if chunked {
		decoded, err := decodeChunkedBody(res.body)
		if err != nil {
			return replayResult{}, fmt.Errorf("decode chunked HTTP response: %w", err)
		}
		res.body = decoded
	}
	return res, nil
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
		// Spell this without n+2: a malicious MaxInt64 chunk size would
		// overflow that addition and turn the subsequent slice into a panic.
		if len(tail) < 2 || n > int64(len(tail)-2) {
			return nil, fmt.Errorf("truncated chunk data")
		}
		out = append(out, tail[:n]...)
		if !bytes.Equal(tail[n:n+2], []byte("\r\n")) {
			return nil, fmt.Errorf("malformed chunk terminator")
		}
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
