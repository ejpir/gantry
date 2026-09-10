// Package oauthbridge runs the host-side OAuth loopback callback bridge for a
// sandbox. A guest-side watcher reports loopback TCP listeners independently
// of application and terminal output. The bridge binds matching host-loopback
// ports and replays OAuth callback requests into the guest.
//
// Callback replay reaches the guest through one injected Exec. Listener
// discovery is supplied separately by the daemon's trusted watcher task, so
// this package remains independent of guest process and terminal plumbing.
package oauthbridge

// oauth_bridge.go — transparent OAuth loopback callback bridge.
//
// Agent CLIs (codex, claude, pi, andromeda, …) sign in with an OAuth
// authorization-code flow against a loopback listener INSIDE the sandbox
// (codex: http://localhost:1455/auth/callback, pi:
// http://localhost:53692/callback, claude:
// http://localhost:<random>/callback, andromeda:
// http://localhost:<random>). The CLI prints the authorize
// URL and waits for the provider to redirect the browser to the loopback
// listener — but the browser runs on the HOST, where that port is not the
// sandbox listener. The redirect dies in the host's network stack and login
// never completes.
//
// A daemon-owned helper watches guest procfs for loopback TCP listeners, so
// nested programs and terminal redraws cannot hide a callback port. This
// bridge:
//
//  1. receives bounded snapshots of guest loopback listeners;
//  2. binds matching 127.0.0.1:<port> listeners on the host (loopback only,
//     never LAN);
//  3. accepts only OAuth-shaped result requests and replays them into the
//     sandbox with an internal exec running a bash /dev/tcp one-shot—no MITM
//     and no new egress. The request is made by a process inside the guest
//     netns, exactly where the CLI's loopback listener expects it;
//  4. returns a host-authored completion page and closes the host gate when
//     the guest listener disappears. Guest response bytes are never rendered
//     in the host browser.
//
// Security posture: the bridge is enabled by default, with per-sandbox and
// global opt-outs. Host listeners bind 127.0.0.1 only and are restricted to
// the documented fixed callback ports or the dynamic OAuth range. Listener
// count, replay concurrency, duration, request size, and response size are all
// bounded. Transparent callbacks must carry state and code/error; the guest
// CLI remains authoritative for state and PKCE validation. Only GET path+query
// is replayed to guest loopback; browser headers and cookies never cross the
// boundary.
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
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxActiveListeners    = 16
	maxFailedPorts        = 64
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
	custody       bool
	ln            net.Listener
	ttl           *time.Timer
	ttlGeneration uint64
}

// Enabled resolves the persisted setting and GANTRY_OAUTH_BRIDGE override.
// Guest-tool planning and bridge construction share it so the watcher helper
// is neither omitted nor delivered unnecessarily.
func Enabled(enabled bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GANTRY_OAUTH_BRIDGE"))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return enabled
	}
}

// New creates the default-on, resource-bounded bridge. It returns nil when the
// bridge is switched off, which callers treat as "no bridge" rather than an
// error.
func New(exec Exec, enabled bool) *Bridge {
	if exec == nil || !Enabled(enabled) {
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

// allowedCallbackPort keeps automatic host binds away from ordinary service
// ports. Codex and Pi use fixed legacy ports; other CLIs use ephemeral ports
// selected from Linux's normal range.
func allowedCallbackPort(port int) bool {
	return port == 1455 || port == 53692 || port >= 32768 && port <= 65535
}

// SetCustodyConsumer installs the custody-mode interception hook: when
// non-nil and returning true, a callback is consumed host-side (daemon token
// exchange) and not replayed into the guest.
func (b *Bridge) SetCustodyConsumer(consume func(port int, u *url.URL) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.custodyConsume = consume
}

// EnsureCallbackPort opens a custody-owned host listener before the custody
// helper prints its authorize URL. Custody does not run a guest HTTP listener;
// its exact pending state is validated by custodyConsume.
func (b *Bridge) EnsureCallbackPort(port int) bool {
	return b.ensureListener(port, true)
}

// OpenGuestListener mirrors a newly observed guest-loopback listener on host
// loopback. The endpoint is an OAuth request gate, not a general port forward.
func (b *Bridge) OpenGuestListener(port int) bool {
	return b.ensureListener(port, false)
}

// CloseGuestListener removes a transparent listener when the corresponding
// guest socket disappears. Custody-owned listeners have an independent
// lifecycle and are never affected by procfs snapshots.
func (b *Bridge) CloseGuestListener(port int) {
	b.mu.Lock()
	delete(b.failed, port)
	l := b.listeners[port]
	if l == nil || l.custody {
		b.mu.Unlock()
		return
	}
	b.closeExactListenerLocked(l)
	b.mu.Unlock()
	b.logf("closed host listener on 127.0.0.1:%d (guest listener closed)", port)
}

// CloseGuestListeners tears down every transparently discovered listener when
// the watcher exits. Custody callbacks remain available for their own TTL.
func (b *Bridge) CloseGuestListeners() {
	b.mu.Lock()
	var closed []int
	for port, l := range b.listeners {
		if l.custody {
			continue
		}
		b.closeExactListenerLocked(l)
		closed = append(closed, port)
	}
	b.failed = map[int]bool{}
	b.mu.Unlock()
	for _, port := range closed {
		b.logf("closed host listener on 127.0.0.1:%d (guest watcher stopped)", port)
	}
}

// ensureListener binds 127.0.0.1:port on the host once. Bind failures are
// remembered until the guest closes and reopens that port.
func (b *Bridge) ensureListener(port int, custody bool) bool {
	if !allowedCallbackPort(port) {
		return false
	}
	b.mu.Lock()
	if existing, ok := b.listeners[port]; ok {
		if existing.custody != custody {
			b.mu.Unlock()
			return false
		}
		if custody {
			b.resetListenerLifetimeLocked(existing)
		}
		b.mu.Unlock()
		return true
	}
	if b.failed[port] {
		b.mu.Unlock()
		return false
	}
	if len(b.listeners) >= maxActiveListeners {
		b.mu.Unlock()
		b.logf("listener limit reached (%d); ignoring guest loopback port %d", maxActiveListeners, port)
		return false
	}
	// Keep the lock across bind so concurrent snapshots cannot race the same
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
	l := &listener{port: port, custody: custody, ln: ln}
	b.listeners[port] = l
	// Transparent lifetime follows the observed guest socket. Custody has no
	// guest listener, so retain its bounded abandoned-flow TTL.
	if custody {
		b.resetListenerLifetimeLocked(l)
	}
	b.mu.Unlock()
	if custody {
		b.logf("OAuth custody callback: listening on host http://127.0.0.1:%d", port)
	} else {
		b.logf("guest loopback listener detected: OAuth callback gate on host http://127.0.0.1:%d", port)
	}
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
	// Close before making the port available for reuse. Otherwise a watcher
	// snapshot can race the still-open socket and cache an EADDRINUSE failure.
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

// handleCallback serves one browser request. Transparent listeners accept
// only OAuth-shaped results; the guest CLI performs authoritative state and
// PKCE validation. Custody callbacks retain their exact host-side state gate.
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
		q := r.URL.Query()
		if q.Get("state") == "" || (q.Get("code") == "" && q.Get("error") == "") {
			http.Error(w, "gantry oauth bridge: not an OAuth callback result", http.StatusNotFound)
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
		// The guest watcher closes this gate with the underlying socket. Do not
		// assume the application is one-shot: some unmodified CLIs reuse a
		// loopback listener for later login attempts.
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
// bash is present in every gantry image (the default shell); containers share
// the VM netns. Using localhost lets the resolver reach IPv4 or IPv6 loopback.
const devTCPReplayScript = `set -u
port=$1; uri=$2
exec 3<>"/dev/tcp/localhost/$port" || { echo "oauth-replay: cannot connect to localhost:$port (CLI not listening?)" >&2; exit 97; }
printf 'GET %s HTTP/1.0\r\nHost: localhost:%s\r\nUser-Agent: gantry-oauth-bridge\r\nAccept: */*\r\nConnection: close\r\n\r\n' "$uri" "$port" >&3 || { echo "oauth-replay: write failed" >&2; exit 98; }
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
