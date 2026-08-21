// SPDX-License-Identifier: Apache-2.0

// Remote (streamable-HTTP) MCP upstreams with credential injection.
//
// Security posture (docs/mcp-gateway.md, normative):
//   - Credentials are injected by the gateway, resolved host-side; the
//     guest never sees them in requests...
//   - ...and never in responses either: every injected value joins the
//     upstream's redaction set, so a reflecting or compromised remote
//     cannot launder its own token back into the guest transcript.
//   - Credential-to-origin binding: injected headers only ever go to the
//     configured origin. Any redirect on a credentialed upstream is a
//     hard error — never followed, never silent.
//   - SSRF guard with dial pinning: the hostname is resolved and
//     validated INSIDE DialContext, and the validated IP itself is
//     dialed — there is no check/connect TOCTOU for DNS rebinding to
//     exploit. Non-public targets (loopback, RFC1918, link-local —
//     which includes cloud metadata 169.254.169.254 — CGNAT, multicast)
//     are refused unless the URL host was explicitly a loopback literal
//     (the test escape hatch, mirroring the OAuth mock-AS pattern).
//   - HTTPS with verified TLS; plain HTTP only to loopback literals.
//   - Bounded: 1 MiB response cap, dial/TLS/header timeouts, and the
//     caller's context governs the whole exchange.

package mcpgw

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/mcpgw/mcpproto"
)

// ValidateRemoteURL enforces the remote-upstream URL rules. It returns
// allowPrivate=true when the host is a loopback literal — the dial guard
// then permits non-public addresses for this server (mock servers in
// tests; the OAuth mock-AS pattern).
func ValidateRemoteURL(raw string) (allowPrivate bool, err error) {
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
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xC0 == 64 { // 100.64.0.0/10 CGNAT
			return false
		}
		if v4[0] == 192 && v4[1] == 0 && v4[2] == 0 { // 192.0.0.0/24
			return false
		}
		if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) { // 198.18.0.0/15 benchmarking
			return false
		}
	}
	return true
}

// pinnedTransport builds an http.Transport whose DialContext resolves,
// validates, and dials a pinned IP — validation and use are the same
// address, so DNS rebinding between check and connect has no window.
// TLS ServerName is still derived from the URL hostname by net/http.
func pinnedTransport(allowPrivate bool) *http.Transport {
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
		if !isPublicIP(ip) && !allowPrivate {
			return nil, fmt.Errorf("ssrf: %s resolved to non-public %s — refused", host, ip)
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	return t
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
	logf    LogFunc
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
	allowPrivate, err := ValidateRemoteURL(srv.URL)
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
	client := &http.Client{Transport: pinnedTransport(allowPrivate)}
	if len(headers) > 0 {
		// Credential-to-origin binding: a redirect would carry the
		// injected headers to a different origin — hard error, never
		// followed. (Uncredentialed upstreams keep the default policy;
		// the dial guard still vets every hop's origin.)
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirect refused: credentialed upstreams never follow redirects")
		}
	}
	u := &httpUpstream{
		name:    srv.Name,
		url:     srv.URL,
		headers: headers,
		redact:  redact,
		logf:    logf,
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
	if resp.Error != nil {
		// A reflecting upstream could embed the injected credential in an
		// error message — redact error text too, not just results.
		msg := redactBytes([]byte(resp.Error.Message), u.redact)
		return nil, fmt.Errorf("upstream %s error %d: %s", u.name, resp.Error.Code, msg)
	}
	return redactBytes(resp.Result, u.redact), nil
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
	if _, err := u.post(ctx, frame, false); err != nil && u.logf != nil {
		u.logf("mcp: upstream %s notification %s failed: %v", u.name, method, err)
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
		// Include a redacted, length-capped snippet of the error body —
		// an upstream 401 page often says why, and must not leak the
		// injected credential back to the guest.
		snip, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("upstream %s HTTP %d: %s", u.name, resp.StatusCode,
			redactBytes(snip, u.redact))
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
