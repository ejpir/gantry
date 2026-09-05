// SPDX-License-Identifier: Apache-2.0

// Remote (streamable-HTTP) MCP upstreams with credential injection.
//
// Security posture (docs/mcp-gateway.md, normative):
//   - Credentials are injected by the gateway, resolved host-side; the
//     guest never sees them in requests. Exact occurrences in decoded JSON
//     strings are masked on responses to contain accidental reflection.
//     This is not DLP against a malicious credentialed upstream, which can
//     transform or covertly encode a credential it necessarily receives.
//   - Credential-to-origin binding: injected headers only ever go to the
//     configured origin. Any redirect on a credentialed upstream is a
//     hard error — never followed, never silent.
//   - SSRF guard with dial pinning: the hostname is resolved and
//     validated INSIDE DialContext, and the validated IP itself is
//     dialed — there is no check/connect TOCTOU for DNS rebinding to
//     exploit. Non-public targets (loopback, RFC1918, link-local —
//     which includes cloud metadata 169.254.169.254 — CGNAT, multicast)
//     are refused. An explicitly loopback URL may resolve only to another
//     loopback address (the test escape hatch, never a general private-net bypass).
//   - HTTPS with verified TLS; plain HTTP only to loopback literals.
//   - Bounded: 1 MiB response cap, dial/TLS/header timeouts, and the
//     caller's context governs the whole exchange.

package mcpgw

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/mcpgw/mcpproto"
)

// ValidateRemoteURL enforces the remote-upstream URL rules. It returns
// loopbackOnly=true when the host is a loopback literal. That exception is
// deliberately scoped to loopback addresses; it must never admit arbitrary
// RFC1918, link-local, or metadata targets.
// AuditRemoteOrigin returns endpoint metadata safe for the audit trail. Query
// strings and paths may contain bearer material and are deliberately omitted.
func AuditRemoteOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "<invalid-origin>"
	}
	return u.Scheme + "://" + u.Host
}

func ValidateRemoteURL(raw string) (loopbackOnly bool, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return false, fmt.Errorf("bad URL: %w", err)
	}
	if u.User != nil {
		return false, fmt.Errorf("credentials in the URL are forbidden — use auth= instead")
	}
	host := u.Hostname()
	if host == "" {
		return false, fmt.Errorf("URL must be https://host[:port]/path")
	}
	loop := isLoopbackHost(host)
	switch u.Scheme {
	case "https":
		// Any host; the dial guard still vetoes non-public targets.
	case "http":
		if !loop {
			return false, fmt.Errorf("plain HTTP is only allowed to loopback hosts (got %s)", host)
		}
	default:
		return false, fmt.Errorf("scheme must be https (http only to loopback), got %q", u.Scheme)
	}
	// Literal non-public IPs are knowable without DNS — refuse them here
	// so misconfiguration fails loudly at start time, not on first call.
	if ip := net.ParseIP(host); ip != nil && !isPublicIP(ip) && !loop {
		return false, fmt.Errorf("refusing non-public target %s (SSRF guard)", host)
	}
	return loop, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// isPublicIP reports whether ip is a globally routable unicast address.
// net.IP.IsGlobalUnicast is NOT sufficient (it returns true for private
// and loopback space), so the dangerous ranges are rejected explicitly.
var publicIPv6Prefix = netip.MustParsePrefix("2000::/3")

var nonPublicPrefixes = []netip.Prefix{
	// IPv4 special-use, documentation, benchmarking, and reserved space.
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),

	// IPv6 translation/tunnelling mechanisms can reach an embedded IPv4
	// target; special-use and documentation ranges are not public upstreams.
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func isPublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	// Currently allocated globally routable IPv6 unicast space is 2000::/3.
	// Refusing future/reserved blocks is safer than treating them as SSRF-safe.
	if addr.Is6() && !publicIPv6Prefix.Contains(addr) {
		return false
	}
	return true
}

// pinnedTransport builds an http.Transport whose DialContext resolves,
// validates, and dials a pinned IP — validation and use are the same
// address, so DNS rebinding between check and connect has no window.
// TLS ServerName is still derived from the URL hostname by net/http.
func pinnedTransport(loopbackOnly bool) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	resolver := &net.Resolver{}
	t := &http.Transport{
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          4,
	}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("ssrf: resolve %s: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("ssrf: %s resolved to no addresses", host)
		}
		ip := ips[0].IP // pinned: this validated address is the one dialed
		if loopbackOnly {
			if !ip.IsLoopback() {
				return nil, fmt.Errorf("ssrf: loopback target %s resolved to non-loopback %s — refused", host, ip)
			}
		} else if !isPublicIP(ip) {
			return nil, fmt.Errorf("ssrf: %s resolved to non-public %s — refused", host, ip)
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	return t
}

// DialRemote is the trusted supervisor dial broker. Validation, DNS
// resolution, address classification, and the actual connect use one pinned
// path; callers receive only the connected stream. TLS remains in the MCP
// worker and therefore is not parsed in the supervisor.
func DialRemote(ctx context.Context, rawURL string) (net.Conn, error) {
	loopbackOnly, err := ValidateRemoteURL(rawURL)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return pinnedTransport(loopbackOnly).DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
}

// httpUpstream speaks MCP streamable-HTTP to one remote server: each
// request is a POST accepting either a single JSON response or an SSE
// stream; notifications expect 202. One exchange at a time — the session
// mux already provides concurrency across servers.
type httpUpstream struct {
	name    string
	url     string
	headers map[string]string // injected, pre-resolved; values never logged
	redact  [][]byte
	emit    func(Event)
	client  *http.Client

	mu     sync.Mutex
	nextID uint64

	sessionID string // Mcp-Session-Id assigned by the server, if any
	proto     string // negotiated protocol version, sent on later requests
	closed    bool
}

// startHTTPUpstream builds the transport, resolves any dynamic credential
// (TokenFunc — custody access tokens are re-read per session, so a
// refreshed token reaches new sessions), and runs the MCP handshake.
func startHTTPUpstream(ctx context.Context, logf LogFunc, srv Server) (*httpUpstream, error) {
	var emit func(Event)
	if logf != nil {
		emit = func(event Event) { logf("%s", event.String()) }
	}
	return startHTTPUpstreamForSession(ctx, emit, srv, "")
}

func startHTTPUpstreamForSession(ctx context.Context, emit func(Event), srv Server, sessionToken string) (*httpUpstream, error) {
	loopbackOnly, err := ValidateRemoteURL(srv.URL)
	if err != nil {
		return nil, fmt.Errorf("remote server %s: %w", srv.Name, err)
	}
	headers := make(map[string]string, len(srv.Headers)+1)
	redact := append([][]byte{}, srv.Redact...)
	for k, v := range srv.Headers {
		headers[k] = v
		if v != "" {
			redact = append(redact, []byte(v))
			// A reflected/leaked response typically carries the bare
			// credential, not the full "Bearer …" header value.
			if tok, ok := strings.CutPrefix(v, "Bearer "); ok && tok != "" {
				redact = append(redact, []byte(tok))
			}
		}
	}
	if srv.TokenFunc != nil {
		tok, err := srv.TokenFunc()
		if err != nil {
			return nil, fmt.Errorf("remote server %s: custody token: %w", srv.Name, err)
		}
		if tok != "" {
			headers["Authorization"] = "Bearer " + tok
			redact = append(redact, []byte(tok))
		}
	}
	if srv.Credentials != nil {
		credential, err := srv.Credentials(ctx, sessionToken)
		if err != nil {
			return nil, fmt.Errorf("remote server %s: credential unavailable", srv.Name)
		}
		for key, value := range credential.Headers {
			headers[key] = value
			if value != "" {
				redact = append(redact, []byte(value))
				if token, ok := strings.CutPrefix(value, "Bearer "); ok && token != "" {
					redact = append(redact, []byte(token))
				}
			}
		}
		redact = append(redact, credential.Redact...)
	}
	transport := pinnedTransport(loopbackOnly)
	if srv.Dial != nil {
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return srv.Dial(ctx, sessionToken)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: srv.TLSRoots, MinVersion: tls.VersionTLS12}
	}
	client := &http.Client{Transport: transport}
	// Redirects are never followed. Besides binding injected credentials to
	// one origin, this prevents a loopback test/development endpoint from
	// redirecting through its loopback-only transport to a private target.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("redirect refused: MCP upstreams never follow redirects")
	}
	u := &httpUpstream{
		name:    srv.Name,
		url:     srv.URL,
		headers: headers,
		redact:  redact,
		emit:    emit,
		client:  client,
	}
	initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := u.Call(initCtx, "initialize", initializeParams()); err != nil {
		return nil, fmt.Errorf("upstream initialize: %w", err)
	}
	u.Notify("notifications/initialized", nil)
	return u, nil
}

func (u *httpUpstream) close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.closed = true
	u.client.CloseIdleConnections()
}

// Call POSTs one request and returns its (redacted) result object.
func (u *httpUpstream) Call(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil, fmt.Errorf("upstream %s is closed", u.name)
	}
	u.nextID++
	frame, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(fmt.Sprintf("%d", u.nextID)),
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return nil, err
	}
	raw, err := u.post(ctx, frame, true)
	if err != nil {
		return nil, err
	}
	var resp struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("upstream %s: bad response frame: %w", u.name, err)
	}
	if (len(resp.Result) != 0) == (resp.Error != nil) {
		return nil, fmt.Errorf("upstream %s: response must contain exactly one of result or error", u.name)
	}
	if resp.Error != nil {
		// A reflecting upstream could embed the injected credential in an
		// error message — redact error text too, not just results.
		msg := redactBytes([]byte(resp.Error.Message), u.redact)
		return nil, fmt.Errorf("upstream %s error %d: %s", u.name, resp.Error.Code, msg)
	}
	result, err := redactJSON(resp.Result, u.redact)
	if err != nil {
		return nil, fmt.Errorf("upstream %s result redaction failed", u.name)
	}
	return result, nil
}

// Notify POSTs a notification and expects 202 Accepted. Failures are
// audited, not returned (matching stdioUpstream.Notify).
func (u *httpUpstream) Notify(method string, params json.RawMessage) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return
	}
	frame, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params,omitempty"`
	}{"2.0", method, params})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := u.post(ctx, frame, false); err != nil && u.emit != nil {
		u.emit(Event{Type: EventNotificationFail, Server: u.name, Method: method})
	}
}

// post sends one frame and returns the JSON-RPC response object for it,
// or nil for a notification acknowledgement. Bodies are capped at
// MaxFrameBytes; the injected headers ride only on requests to the
// configured URL (the client never follows redirects with them).
func (u *httpUpstream) post(ctx context.Context, frame []byte, wantResp bool) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(frame))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range u.headers {
		req.Header.Set(k, v)
	}
	if u.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", u.sessionID)
	}
	if u.proto != "" {
		req.Header.Set("MCP-Protocol-Version", u.proto)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream %s: %w", u.name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" && len(sid) < 256 {
		u.sessionID = sid
	}
	if resp.StatusCode == http.StatusAccepted && !wantResp {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Upstream bodies are tool payload, not audit metadata. Do not carry a
		// preview into the returned error: callers audit failures host-side.
		return nil, fmt.Errorf("upstream %s HTTP %d", u.name, resp.StatusCode)
	}
	if u.proto == "" {
		u.proto = protocolVersion
	}

	body, err := readCapped(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("upstream %s: %w", u.name, err)
	}
	switch ct := resp.Header.Get("Content-Type"); {
	case strings.HasPrefix(ct, "application/json"):
		return json.RawMessage(body), nil
	case strings.HasPrefix(ct, "text/event-stream"):
		return sseResponse(body)
	default:
		return nil, fmt.Errorf("upstream %s: unexpected content type %q", u.name, ct)
	}
}

func readCapped(r io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, mcpproto.MaxFrameBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > mcpproto.MaxFrameBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", mcpproto.MaxFrameBytes)
	}
	return raw, nil
}

// sseResponse scans an SSE body for the first JSON-RPC frame carrying a
// response (id + result/error). Comments and unknown events are ignored;
// an EOF without a response is an error. (Requests in flight are
// serialized, so the first response frame is ours.)
func sseResponse(body []byte) (json.RawMessage, error) {
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), mcpproto.MaxFrameBytes)
	for sc.Scan() {
		data, ok := bytes.CutPrefix(bytes.TrimSpace(sc.Bytes()), []byte("data:"))
		if !ok {
			continue
		}
		data = bytes.TrimSpace(data)
		var probe struct {
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *rpcError       `json:"error"`
		}
		if err := json.Unmarshal(data, &probe); err != nil {
			continue // not JSON-RPC: ignore
		}
		if len(probe.ID) > 0 && (len(probe.Result) > 0 || probe.Error != nil) {
			return json.RawMessage(data), nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("SSE stream ended without a response frame")
}
