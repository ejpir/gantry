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
//  4. returns a host-authored completion page and closes the listener once a
//     callback carrying code=/error= has been delivered. Guest response bytes
//     are never rendered in the host browser.
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
	completionPage        = "<!doctype html><meta charset=utf-8><title>OAuth callback delivered</title><h2>OAuth callback delivered</h2><p>Return to the sandbox CLI for the final sign-in result.</p>"
	custodyPage           = "<!doctype html><meta charset=utf-8><title>OAuth callback received</title><h2>OAuth callback received</h2><p>Gantry is completing token custody on the host. Return to the sandbox CLI for the final result.</p>"
	failurePage           = "<!doctype html><meta charset=utf-8><title>OAuth callback failed</title><h2>Sign-in could not be completed</h2><p>Gantry could not deliver the OAuth callback to the CLI inside the sandbox.</p><p>Check that the CLI is still waiting for sign-in, then retry. Details are in the sandbox daemon log.</p>"
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
	port          int
	expectedPath  string
	expectedState string
	validateState bool
	custody       bool
	ln            net.Listener
	ttl           *time.Timer
	ttlGeneration uint64
}

type callbackTarget struct {
	port          int
	path          string
	state         string
	validateState bool
	custody       bool
}

var (
	// reOAuthRedirectURI matches the redirect_uri query parameter of a
	// printed authorize URL, URL-encoded or not:
	//   redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback
	//   redirect_uri=http://localhost:53692/callback
	reOAuthRedirectURI = regexp.MustCompile(`redirect_uri=([^&\s"'()<>\[\]{}\x1b]+)`)
	// reOAuthLoopbackURL matches a directly printed callback URL:
	//   http://localhost:53692/callback  http://127.0.0.1:1455/auth/callback
	// Match the whole printed URL token, then inspect its parsed path. Keeping
	// the suffix and query is necessary for /callback/suffix and ?state= flows.
	reOAuthLoopbackURL = regexp.MustCompile(`http://(?:localhost|127\.0\.0\.1):(\d{1,5})/[^\s"'()<>\[\]{}\x1b]*`)
)

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
	targets := callbackTargets(text)
	out := make([]int, 0, len(targets))
	for _, target := range targets {
		out = append(out, target.port)
	}
	return out
}

func callbackTargets(text string) []callbackTarget {
	byPort := map[int]callbackTarget{}
	add := func(target callbackTarget) {
		if !allowedCallbackPort(target.port) {
			return
		}
		if old, ok := byPort[target.port]; ok {
			merged, _ := mergeCallbackTarget(old, target)
			byPort[target.port] = merged
			return
		}
		byPort[target.port] = target
	}
	for _, m := range reOAuthRedirectURI.FindAllStringSubmatchIndex(text, -1) {
		raw, err := url.QueryUnescape(trimPrintedURLToken(text[m[2]:m[3]]))
		if err != nil {
			raw = text[m[2]:m[3]]
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
			add(callbackTarget{port: p, path: u.Path, state: callbackStateNear(text, m[0], m[1]), validateState: true})
		}
	}
	for _, m := range reOAuthLoopbackURL.FindAllStringSubmatchIndex(text, -1) {
		u, parseErr := url.Parse(trimPrintedURLToken(text[m[0]:m[1]]))
		if parseErr != nil || !strings.Contains(strings.ToLower(u.Path), "callback") {
			continue
		}
		if p, err := strconv.Atoi(text[m[2]:m[3]]); err == nil {
			add(callbackTarget{port: p, path: u.Path, state: u.Query().Get("state"), validateState: true})
		}
	}
	out := make([]callbackTarget, 0, len(byPort))
	for _, target := range byPort {
		out = append(out, target)
	}
	return out
}

func trimPrintedURLToken(raw string) string {
	return strings.TrimRight(raw, ".,;:")
}

// mergeCallbackTarget enriches a target only with observations for the same
// port and path. It never replaces an established non-empty expectation.
func mergeCallbackTarget(old, next callbackTarget) (callbackTarget, bool) {
	merged := old
	if old.port != next.port || old.custody != next.custody {
		return merged, false
	}
	if merged.path == "" || (next.path != "" && strings.HasPrefix(next.path, merged.path)) {
		merged.path = next.path
	}
	samePath := next.path == "" || merged.path == "" || merged.path == next.path
	if samePath && (merged.state == "" || (next.state != "" && strings.HasPrefix(next.state, merged.state))) {
		merged.state = next.state
	}
	if samePath && next.validateState {
		merged.validateState = true
	}
	return merged, merged != old
}

// callbackStateNear extracts state from the same printed authorization URL
// that carried redirect_uri. It also handles a bare query fragment used by a
// few CLIs. An unavailable state stays empty and is not guessed.
func callbackStateNear(text string, start, end int) string {
	isBoundary := func(b byte) bool { return strings.ContainsRune(" \t\r\n\"'()<>[]{}\x1b", rune(b)) }
	left := start
	for left > 0 && !isBoundary(text[left-1]) {
		left--
	}
	right := end
	for right < len(text) && !isBoundary(text[right]) {
		right++
	}
	token := trimPrintedURLToken(text[left:right])
	if u, err := url.Parse(token); err == nil {
		if state := u.Query().Get("state"); state != "" {
			return state
		}
	}
	if values, err := url.ParseQuery(text[start:right]); err == nil {
		return values.Get("state")
	}
	return ""
}

// SetCustodyConsumer installs the custody-mode interception hook: when
// non-nil and returning true, a callback is consumed host-side (daemon token
// exchange) and not replayed into the guest.
func (b *Bridge) SetCustodyConsumer(consume func(port int, u *url.URL) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.custodyConsume = consume
}

// EnsureCallbackPort opens the host loopback listener for a custody flow
// before any authorize URL has been sniffed (the guest helper declares
// its redirect port up front). It reports whether the allowed port was
// actually opened (or was already custody-owned); the caller fails loudly on
// bind, listener-kind conflict, or listener-limit errors rather than stranding
// the browser.
func (b *Bridge) EnsureCallbackPort(port int) bool {
	if !allowedCallbackPort(port) {
		return false
	}
	// Custody validates its nonce in custodyConsume. Mark its listener as
	// custody-owned so stdout sniffing cannot weaken or replace that check and
	// an unknown-state callback can never fall through to guest replay.
	return b.ensureListenerTarget(callbackTarget{port: port, custody: true})
}

// SniffWriter returns a writer that forwards every byte unchanged while
// scanning for OAuth callback URLs. Writes are serialized so concurrent relay
// and status output cannot race its rolling buffer or wrapped writer.
func (b *Bridge) SniffWriter(w io.Writer) io.Writer {
	return &sniffWriter{w: w, b: b, seen: map[int]callbackTarget{}}
}

type sniffWriter struct {
	mu  sync.Mutex
	w   io.Writer
	b   *Bridge
	buf []byte // rolling tail window for URLs split across writes
	// A declared session may arm a small number of flows, not walk the
	// entire dynamic port range by printing synthetic authorize URLs.
	seen map[int]callbackTarget
}

func (s *sniffWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.w.Write(p)
	if n > 0 {
		s.buf = append(s.buf, p[:n]...)
		if len(s.buf) > 16384 {
			s.buf = s.buf[len(s.buf)-16384:]
		}
		for _, target := range callbackTargets(string(s.buf)) {
			old, ok := s.seen[target.port]
			if !ok && len(s.seen) >= maxPortsPerSession {
				continue
			}
			if !ok {
				s.seen[target.port] = target
				s.b.ensureListenerTarget(target)
				continue
			}
			merged, changed := mergeCallbackTarget(old, target)
			if changed {
				s.seen[target.port] = merged
				// Enrichment is allowed only while the original listener is
				// still active. Old bytes in the rolling window must never
				// reopen a one-shot or expired flow.
				s.b.enrichListenerTarget(merged)
			}
		}
	}
	return n, err
}

// ensureListener binds 127.0.0.1:port on the host once. Bind failures are
// remembered so repeated prints of the same URL don't spam.
func (b *Bridge) ensureListener(port int) bool {
	return b.ensureListenerTarget(callbackTarget{port: port})
}

func (b *Bridge) ensureListenerTarget(target callbackTarget) bool {
	return b.ensureListenerTargetMode(target, true)
}

func (b *Bridge) enrichListenerTarget(target callbackTarget) bool {
	return b.ensureListenerTargetMode(target, false)
}

func (b *Bridge) ensureListenerTargetMode(target callbackTarget, allowCreate bool) bool {
	port := target.port
	if !allowedCallbackPort(port) {
		return false
	}
	b.mu.Lock()
	if existing, ok := b.listeners[port]; ok {
		// Custody and transparent replay have different trust semantics. Never
		// reuse or enrich one kind of listener as the other kind.
		if existing.custody != target.custody {
			b.mu.Unlock()
			return false
		}
		if existing.custody {
			// Multiple custody flows may share a callback port. Keep the
			// listener alive for a full flow lifetime after the latest one is
			// registered; a generation check prevents an old timer callback
			// from closing the refreshed listener.
			b.resetListenerLifetimeLocked(existing)
			b.mu.Unlock()
			return true
		}
		// A URL split across terminal writes may reveal the path first and
		// state later. Enrich an existing listener, but never replace one
		// flow's non-empty expectation with a different value.
		current := callbackTarget{port: port, path: existing.expectedPath, state: existing.expectedState, validateState: existing.validateState}
		merged, _ := mergeCallbackTarget(current, target)
		existing.expectedPath = merged.path
		existing.expectedState = merged.state
		existing.validateState = merged.validateState
		b.mu.Unlock()
		return true
	}
	if !allowCreate {
		b.mu.Unlock()
		return false
	}
	if b.failed[port] {
		b.mu.Unlock()
		return false
	}
	if len(b.listeners) >= maxActiveListeners {
		b.mu.Unlock()
		b.logf("listener limit reached (%d); ignoring callback port %d", maxActiveListeners, port)
		return false
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
		return false
	}
	l := &listener{
		port:          port,
		expectedPath:  target.path,
		expectedState: target.state,
		validateState: target.validateState,
		custody:       target.custody,
		ln:            ln,
	}
	b.listeners[port] = l
	// A flow the user abandons must not hold the host port forever.
	b.resetListenerLifetimeLocked(l)
	b.mu.Unlock()
	b.logf("OAuth callback detected: listening on host http://127.0.0.1:%d (replaying into the sandbox)", port)
	go b.serve(l)
	return true
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
	b.closeExactListenerLocked(l)
	b.mu.Unlock()
	b.logf("closed host listener on 127.0.0.1:%d", l.port)
}

func (b *Bridge) closeExactListenerLocked(l *listener) {
	// Close before making the port available for reuse. Otherwise a scanner
	// can observe the deleted map entry, race the still-open socket, and
	// permanently cache an EADDRINUSE failure for this bridge.
	if l.ttl != nil {
		l.ttl.Stop()
	}
	_ = l.ln.Close()
	delete(b.listeners, l.port)
}

func (b *Bridge) resetListenerLifetimeLocked(l *listener) {
	if l.ttl != nil {
		l.ttl.Stop()
	}
	l.ttlGeneration++
	generation := l.ttlGeneration
	l.ttl = time.AfterFunc(b.lifetime(), func() { b.closeExpiredListener(l, generation) })
}

func (b *Bridge) closeExpiredListener(l *listener, generation uint64) {
	b.mu.Lock()
	if b.listeners[l.port] != l || l.ttlGeneration != generation {
		b.mu.Unlock()
		return
	}
	b.closeExactListenerLocked(l)
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

// handleCallback serves one browser request: validate and deliver the
// path+query, then return a host-authored page. After a request carrying the
// OAuth result (code=/error=) completes, the flow is done and the listener
// closes.
func (b *Bridge) handleCallback(l *listener) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		setBrowserSecurityHeaders(w)
		if r.Method != http.MethodGet {
			http.Error(w, "gantry oauth bridge: only GET callbacks are replayed", http.StatusMethodNotAllowed)
			return
		}
		uri := r.URL.RequestURI()
		if len(uri) > maxRequestURIBytes {
			http.Error(w, "gantry oauth bridge: callback URL too long", http.StatusRequestURITooLong)
			return
		}
		b.mu.Lock()
		expectedPath, expectedState, validateState := l.expectedPath, l.expectedState, l.validateState
		b.mu.Unlock()
		if expectedPath != "" && r.URL.Path != expectedPath {
			http.Error(w, "gantry oauth bridge: callback path mismatch", http.StatusNotFound)
			return
		}
		if validateState && r.URL.Query().Get("state") != expectedState {
			http.Error(w, "gantry oauth bridge: callback state mismatch", http.StatusNotFound)
			return
		}
		if !l.custody && validateState && expectedState == "" {
			q := r.URL.Query()
			if q.Get("code") != "" || q.Get("error") != "" {
				http.Error(w, "gantry oauth bridge: callback state was not captured", http.StatusNotFound)
				return
			}
		}
		if l.custody {
			// Custody callbacks must be claimed by an exact pending state. An
			// unknown callback is never transparently replayed: otherwise a
			// sandbox that won a fixed-port bind race could receive another
			// sandbox's authorization code.
			b.mu.Lock()
			consume := b.custodyConsume
			b.mu.Unlock()
			if consume == nil || !consume(l.port, r.URL) {
				http.Error(w, "gantry oauth bridge: no matching custody flow", http.StatusNotFound)
				return
			}
			writeBrowserPage(w, http.StatusOK, custodyPage)
			// A custody listener can serve several pending flows on one port.
			// Its refreshed lifetime, rather than one callback, closes it.
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
			writeBrowserPage(w, http.StatusBadGateway, failurePage)
			return
		}
		if res.status < 200 || res.status > 599 {
			b.logf("replay response from sandbox port %d used invalid status %d", l.port, res.status)
			http.Error(w, "gantry oauth bridge: invalid callback response", http.StatusBadGateway)
			return
		}
		// A compromised guest controls the loopback listener. Never relay its
		// status, MIME type, redirect, or body into a host browser: active HTML
		// here would execute under a trusted localhost origin and could access
		// host/LAN services or persist a service worker. The response only
		// confirms that the callback reached the guest; the CLI reports whether
		// sign-in itself succeeded.
		writeBrowserPage(w, http.StatusOK, completionPage)
		if q := r.URL.Query(); q.Get("code") != "" || q.Get("error") != "" {
			// OAuth flows are one-shot: the CLI exchanges the code and
			// shuts its listener. Free the host port for the next login.
			time.AfterFunc(2*time.Second, func() { b.closeExactListener(l) })
		}
	}
}

func setBrowserSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	// Clear storage left by an older bridge that rendered guest-controlled
	// localhost content. Cookies are deliberately excluded because they are
	// host-wide rather than port-scoped and may belong to unrelated tooling.
	w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
}

func writeBrowserPage(w http.ResponseWriter, status int, page string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, page)
}

// replayResult records only whether the guest listener answered with HTTP.
// Guest headers and body are deliberately discarded before the host browser
// response is constructed.
type replayResult struct {
	status int
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
	// The isolated session task may append a "client: task exited, status N"
	// trailer to stdout. Strip only that trailer: trimming newlines generally
	// destroys the CRLFCRLF terminator of an empty 302 response.
	if i := bytes.LastIndex(stdout, []byte("\nclient: task exited, status ")); i >= 0 {
		stdout = stdout[:i]
	}
	return parseRawHTTPResponse(stdout)
}

// parseRawHTTPResponse splits a raw HTTP/1.x response (as printed by cat)
// just far enough to validate its status. Guest headers and body are ignored;
// session transports may canonicalize CRLF to LF, so both forms are accepted.
func parseRawHTTPResponse(raw []byte) (replayResult, error) {
	if len(raw) > MaxReplayResponseSize {
		return replayResult{}, fmt.Errorf("HTTP response exceeds %d bytes", MaxReplayResponseSize)
	}
	head, _, lineEnding, ok := splitHTTPResponseHead(raw)
	if !ok {
		return replayResult{}, fmt.Errorf("no HTTP response from the in-sandbox listener: %.200s", raw)
	}
	statusLine, _, _ := bytes.Cut(head, lineEnding)
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
	return replayResult{status: status}, nil
}

func splitHTTPResponseHead(raw []byte) (head, body, lineEnding []byte, ok bool) {
	crlfIndex := bytes.Index(raw, []byte("\r\n\r\n"))
	lfIndex := bytes.Index(raw, []byte("\n\n"))
	switch {
	case crlfIndex >= 0 && (lfIndex < 0 || crlfIndex < lfIndex):
		return raw[:crlfIndex], raw[crlfIndex+4:], []byte("\r\n"), true
	case lfIndex >= 0:
		return raw[:lfIndex], raw[lfIndex+2:], []byte("\n"), true
	default:
		return nil, nil, nil, false
	}
}

// tailBytes returns the last n bytes of b (for error messages).
func tailBytes(b []byte, n int) []byte {
	if len(b) > n {
		return b[len(b)-n:]
	}
	return b
}
