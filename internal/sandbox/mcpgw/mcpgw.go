// Package mcpgw implements the per-sandbox MCP gateway
// (docs/mcp-gateway.md): the guest agent speaks newline-delimited
// JSON-RPC (MCP stdio framing) over one vsock-bridged connection, and the
// gateway fans tool calls out to upstream servers — for milestone 1,
// local stdio servers spawned guest-side through the daemon's exec
// channel.
//
// Security model (normative in the design doc):
//   - default-deny tool policy; authorize/revoke tools are never exposed
//     to the agent;
//   - request IDs are rewritten per upstream so responses can never cross
//     servers or sessions;
//   - configured redactors scrub credential material from anything
//     forwarded back to the guest;
//   - the guest channel carries MCP only: batches and unknown methods are
//     rejected before policy evaluation;
//   - every decision lands on the audit trail with names only — never
//     arguments, results, or token material.
package mcpgw

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/mcpgw/mcpproto"
)

// LogFunc receives audit lines (names and decisions, never values).
type LogFunc func(format string, a ...any)

// ToolPolicy is the per-server allow/deny list. An empty Allow list exposes
// NO tools (default deny). Deny is checked first; authorize/revoke tools
// are denied regardless of either list.
type ToolPolicy struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// Server is one upstream MCP server. Milestone 1 supports local servers
// only: Argv runs guest-side via the daemon's exec channel, stdio piped
// back to the gateway. Redact holds byte strings (credential material)
// scrubbed from anything forwarded back to the guest.
type Server struct {
	Name   string     `json:"name"`
	Argv   []string   `json:"argv,omitempty"`
	Tools  ToolPolicy `json:"tools,omitempty"`
	Redact [][]byte   `json:"-"` // never serialized, never logged
}

// SpawnFunc starts a local server's process and returns its stdio pipes
// plus a kill hook. The daemon wires this to a guest exec-channel session.
type SpawnFunc func(ctx context.Context, argv []string) (stdin io.WriteCloser, stdout io.ReadCloser, kill func(), err error)

// Gateway multiplexes one guest MCP session across upstream servers.
type Gateway struct {
	logf    LogFunc
	spawn   SpawnFunc
	servers map[string]Server
	order   []string

	callTimeout time.Duration
}

// New validates the server set (glob patterns must compile) and returns
// the gateway. logf may be nil (decisions discarded) — it should not be:
// the audit trail is the point.
func New(logf LogFunc, spawn SpawnFunc, servers []Server) (*Gateway, error) {
	g := &Gateway{
		logf:        logf,
		spawn:       spawn,
		servers:     make(map[string]Server, len(servers)),
		callTimeout: 30 * time.Second,
	}
	for _, srv := range servers {
		if srv.Name == "" || strings.Contains(srv.Name, "__") {
			return nil, fmt.Errorf("mcpgw: invalid server name %q", srv.Name)
		}
		if _, dup := g.servers[srv.Name]; dup {
			return nil, fmt.Errorf("mcpgw: duplicate server %q", srv.Name)
		}
		for _, pat := range append(append([]string{}, srv.Tools.Allow...), srv.Tools.Deny...) {
			if _, err := path.Match(pat, ""); err != nil {
				return nil, fmt.Errorf("mcpgw: server %s: bad tool pattern %q: %w", srv.Name, pat, err)
			}
		}
		g.servers[srv.Name] = srv
		g.order = append(g.order, srv.Name)
	}
	return g, nil
}

func (g *Gateway) auditf(format string, a ...any) {
	if g.logf != nil {
		g.logf(format, a...)
	}
}

// --- JSON-RPC plumbing ---------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeServerError    = -32000
)

// protocolVersion is the MCP revision the gateway speaks. The fs server
// answers the same; when the gateway grows remote upstreams (milestone 2)
// version negotiation moves behind the upstream client.
const protocolVersion = "2025-06-18"

// maxInFlight bounds concurrent requests per guest session; a runaway
// agent gets an error instead of exhausting upstream sessions.
const maxInFlight = 16

// Serve handles one guest MCP session until EOF, a fatal frame error, or
// ctx cancellation. All upstreams started for the session are killed when
// it ends.
func (g *Gateway) Serve(ctx context.Context, rw io.ReadWriteCloser) error {
	defer func() { _ = rw.Close() }()
	g.auditf("mcp: session open")

	sess := &session{
		g:         g,
		wmu:       new(sync.Mutex),
		w:         rw,
		upstreams: make(map[string]*stdioUpstream),
		sem:       make(chan struct{}, maxInFlight),
	}
	defer sess.closeAll()

	var wg sync.WaitGroup
	scanner := bufio.NewScanner(rw)
	scanner.Buffer(make([]byte, 64*1024), mcpproto.MaxFrameBytes)
	scanner.Split(scanLines)
	var calls, denied int
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		if line[0] == '[' {
			sess.reply(nil, nil, &rpcError{codeInvalidRequest, "batch requests are not supported"})
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			sess.reply(nil, nil, &rpcError{codeParseError, "malformed JSON-RPC frame"})
			continue
		}
		if req.JSONRPC != "2.0" || req.Method == "" {
			sess.reply(req.ID, nil, &rpcError{codeInvalidRequest, "not a JSON-RPC 2.0 request"})
			continue
		}
		if len(req.ID) == 0 {
			// Notification: no response. Cancellation finesse is a later
			// milestone; notifications/initialized and friends are simply
			// consumed.
			continue
		}
		select {
		case sess.sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		default:
			denied++
			sess.reply(req.ID, nil, &rpcError{codeServerError, "gateway busy: too many in-flight requests"})
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sess.sem }()
			c, d := sess.dispatch(ctx, &req)
			calls += c
			denied += d
		}()
	}
	wg.Wait()
	g.auditf("mcp: session closed (%d calls, %d denied)", calls, denied)
	if err := scanner.Err(); err != nil && err != io.EOF {
		return fmt.Errorf("mcpgw: session read: %w", err)
	}
	return nil
}

// scanLines splits on '\n' (carriage returns tolerated).
func scanLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := strings.IndexByte(string(data), '\n'); i >= 0 {
		line := data[:i]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		return i + 1, line, nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// session is one guest connection's state.
type session struct {
	g   *Gateway
	wmu *sync.Mutex
	w   io.Writer

	mu        sync.Mutex
	upstreams map[string]*stdioUpstream
	sem       chan struct{}
}

func (s *session) reply(id json.RawMessage, result any, rerr *rpcError) {
	resp := rpcResponse{JSONRPC: "2.0", ID: id, Result: result, Error: rerr}
	raw, err := json.Marshal(resp)
	if err != nil {
		return // a marshal failure here is a gateway bug; drop rather than corrupt the stream
	}
	raw = append(raw, '\n')
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, _ = s.w.Write(raw)
}

// dispatch routes one request; it returns (calls, denied) for the session
// audit counters.
func (s *session) dispatch(ctx context.Context, req *rpcRequest) (int, int) {
	switch req.Method {
	case "initialize":
		s.reply(req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "gantry-mcp-gateway", "version": "1.0.0"},
		}, nil)
		return 0, 0
	case "ping":
		s.reply(req.ID, map[string]any{}, nil)
		return 0, 0
	case "tools/list":
		s.toolsList(ctx, req)
		return 0, 0
	case "tools/call":
		return 1, s.toolsCall(ctx, req)
	default:
		s.reply(req.ID, nil, &rpcError{codeMethodNotFound, "method not supported by the gantry MCP gateway"})
		return 0, 0
	}
}

// upstream returns the started upstream for srv, spawning and handshaking
// it on first use.
func (s *session) upstream(ctx context.Context, srv Server) (*stdioUpstream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.upstreams[srv.Name]; ok {
		return u, nil
	}
	if s.g.spawn == nil {
		return nil, fmt.Errorf("no spawn hook wired")
	}
	u, err := startStdioUpstream(ctx, s.g.logf, s.g.spawn, srv)
	if err != nil {
		s.g.auditf("mcp: upstream %s spawn failed: %v", srv.Name, err)
		return nil, err
	}
	s.upstreams[srv.Name] = u
	s.g.auditf("mcp: upstream %s started (argv head %q)", srv.Name, srv.Argv[0])
	return u, nil
}

func (s *session) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, u := range s.upstreams {
		u.close()
		s.g.auditf("mcp: upstream %s stopped", name)
	}
	s.upstreams = nil
}

// --- tools ---------------------------------------------------------------

// toolExposed reports whether tool may be shown to and called by the
// agent. Default deny; deny list first; authorize/revoke tools never.
func toolExposed(srv Server, tool string) bool {
	if isAuthTool(tool) || isAuthTool(srv.Name+"__"+tool) {
		return false
	}
	for _, pat := range srv.Tools.Deny {
		if matched, _ := path.Match(pat, tool); matched {
			return false
		}
	}
	if len(srv.Tools.Allow) == 0 {
		return false
	}
	for _, pat := range srv.Tools.Allow {
		if matched, _ := path.Match(pat, tool); matched {
			return true
		}
	}
	return false
}

// isAuthTool mirrors the reference rule that the agent cannot rebind a server's
// authorization: tools named <something>-authorize or -revoke-auth are
// denied regardless of policy.
func isAuthTool(name string) bool {
	return strings.HasSuffix(name, "-authorize") || strings.HasSuffix(name, "-revoke-auth")
}

// splitToolName splits the exposed "<server>__<tool>" form.
func splitToolName(exposed string) (server, tool string, ok bool) {
	i := strings.Index(exposed, "__")
	if i <= 0 || i+2 >= len(exposed) {
		return "", "", false
	}
	return exposed[:i], exposed[i+2:], true
}

type toolDescriptor struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

func (s *session) toolsList(ctx context.Context, req *rpcRequest) {
	var out []toolDescriptor
	hidden := 0
	for _, name := range s.g.order {
		srv := s.g.servers[name]
		u, err := s.upstream(ctx, srv)
		if err != nil {
			continue // audited inside upstream(); one dead server must not break the listing
		}
		callCtx, cancel := context.WithTimeout(ctx, s.g.callTimeout)
		raw, err := u.Call(callCtx, "tools/list", json.RawMessage(`{}`))
		cancel()
		if err != nil {
			s.g.auditf("mcp: tools/list on %s failed: %v", name, err)
			continue
		}
		var result struct {
			Tools []toolDescriptor `json:"tools"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			s.g.auditf("mcp: tools/list on %s: malformed result; skipping server", name)
			continue
		}
		for _, t := range result.Tools {
			if !toolExposed(srv, t.Name) {
				hidden++
				continue
			}
			t.Name = name + "__" + t.Name
			out = append(out, t)
		}
	}
	if out == nil {
		out = []toolDescriptor{}
	}
	s.g.auditf("mcp: tools/list served %d tools across %d servers (%d policy-hidden)", len(out), len(s.g.order), hidden)
	s.reply(req.ID, map[string]any{"tools": out}, nil)
}

// toolsCall routes one call. It returns 1 when policy denied the call
// (for the session audit counters).
func (s *session) toolsCall(ctx context.Context, req *rpcRequest) int {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
		s.reply(req.ID, nil, &rpcError{codeInvalidParams, "tools/call needs params.name"})
		return 0
	}
	server, tool, ok := splitToolName(p.Name)
	srv, known := s.g.servers[server]
	// Deliberately one message for unknown and denied alike: no tool
	// existence oracle for the agent.
	deny := func() int {
		s.g.auditf("mcp: denied call %s (policy)", p.Name)
		s.reply(req.ID, nil, &rpcError{codeServerError, "unknown or disallowed tool"})
		return 1
	}
	if !ok || !known || !toolExposed(srv, tool) {
		return deny()
	}
	u, err := s.upstream(ctx, srv)
	if err != nil {
		s.reply(req.ID, nil, &rpcError{codeServerError, "upstream unavailable"})
		return 0
	}
	s.g.auditf("mcp: call %s__%s", server, tool)
	upstreamParams, _ := json.Marshal(map[string]any{"name": tool, "arguments": p.Arguments})
	callCtx, cancel := context.WithTimeout(ctx, s.g.callTimeout)
	raw, err := u.Call(callCtx, "tools/call", upstreamParams)
	cancel()
	if err != nil {
		s.g.auditf("mcp: call %s__%s upstream error: %v", server, tool, err)
		s.reply(req.ID, nil, &rpcError{codeServerError, "upstream call failed"})
		return 0
	}
	raw = redactBytes(raw, srv.Redact)
	// stdioUpstream.Call already unwraps the result object; forward it
	// verbatim (post-redaction) so isError and content blocks survive.
	s.replyRaw(req.ID, raw)
	return 0
}

// replyRaw writes a pre-encoded result object.
func (s *session) replyRaw(id json.RawMessage, result json.RawMessage) {
	buf := make([]byte, 0, len(id)+len(result)+64)
	buf = append(buf, `{"jsonrpc":"2.0","id":`...)
	buf = append(buf, id...)
	buf = append(buf, `,"result":`...)
	buf = append(buf, result...)
	buf = append(buf, '}', '\n')
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, _ = s.w.Write(buf)
}

const redactionPlaceholder = "[REDACTED-BY-GANTRY-MCP-GATEWAY]"

// redactBytes scrubs credential byte strings from anything returning to
// the guest: a reflecting or compromised upstream must not be able to
// launder its token back into the guest transcript.
func redactBytes(b []byte, redactors [][]byte) []byte {
	for _, secret := range redactors {
		if len(secret) == 0 {
			continue
		}
		for {
			i := indexOf(b, secret)
			if i < 0 {
				break
			}
			out := make([]byte, 0, len(b))
			out = append(out, b[:i]...)
			out = append(out, redactionPlaceholder...)
			out = append(out, b[i+len(secret):]...)
			b = out
		}
	}
	return b
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}

// --- stdio upstream --------------------------------------------------------

// upstreamReply is one decoded response frame from an upstream.
type upstreamReply struct {
	result json.RawMessage
	err    *rpcError
}

// stdioUpstream speaks NDJSON MCP to one spawned server process. Request
// IDs are generated here — guest-chosen IDs never reach an upstream, so
// responses cannot cross servers or sessions.
type stdioUpstream struct {
	name    string
	logf    LogFunc
	stdin   io.WriteCloser
	kill    func()
	redact  [][]byte
	done    chan struct{}
	dieOnce sync.Once

	wmu     sync.Mutex
	pmu     sync.Mutex
	pending map[uint64]chan upstreamReply
	nextID  atomic.Uint64
}

func startStdioUpstream(ctx context.Context, logf LogFunc, spawn SpawnFunc, srv Server) (*stdioUpstream, error) {
	if len(srv.Argv) == 0 {
		return nil, fmt.Errorf("server %s: empty argv", srv.Name)
	}
	stdin, stdout, kill, err := spawn(ctx, srv.Argv)
	if err != nil {
		return nil, err
	}
	u := &stdioUpstream{
		name:    srv.Name,
		logf:    logf,
		stdin:   stdin,
		kill:    kill,
		redact:  srv.Redact,
		done:    make(chan struct{}),
		pending: make(map[uint64]chan upstreamReply),
	}
	go u.readLoop(stdout)
	initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := u.Call(initCtx, "initialize", json.RawMessage(`{"protocolVersion":"`+protocolVersion+`","capabilities":{},"clientInfo":{"name":"gantry-mcp-gateway","version":"1.0.0"}}`)); err != nil {
		u.close()
		return nil, fmt.Errorf("upstream initialize: %w", err)
	}
	u.Notify("notifications/initialized", nil)
	return u, nil
}

func (u *stdioUpstream) auditf(format string, a ...any) {
	if u.logf != nil {
		u.logf(format, a...)
	}
}

// readLoop dispatches response frames to pending calls. A frame that is
// not valid JSON-RPC corrupts the stream's framing assumptions, so the
// upstream is quarantined: killed and audited (docs/mcp-gateway.md
// "stdout hygiene").
func (u *stdioUpstream) readLoop(r io.ReadCloser) {
	defer u.die()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), mcpproto.MaxFrameBytes)
	scanner.Split(scanLines)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var frame struct {
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *rpcError       `json:"error"`
		}
		if err := json.Unmarshal(line, &frame); err != nil {
			u.auditf("mcp: upstream %s sent a non-JSON-RPC frame; killed", u.name)
			return
		}
		if len(frame.ID) == 0 {
			continue // server notification; milestone 1 drops them
		}
		var id uint64
		if err := json.Unmarshal(frame.ID, &id); err != nil {
			u.auditf("mcp: upstream %s echoed a non-numeric id; killed", u.name)
			return
		}
		u.pmu.Lock()
		ch, ok := u.pending[id]
		u.pmu.Unlock()
		if ok {
			ch <- upstreamReply{result: redactBytes(frame.Result, u.redact), err: frame.Error}
		}
	}
}

// die terminates the upstream exactly once and fails every pending call.
func (u *stdioUpstream) die() {
	u.dieOnce.Do(func() {
		close(u.done)
		u.pmu.Lock()
		for id, ch := range u.pending {
			close(ch)
			delete(u.pending, id)
		}
		u.pmu.Unlock()
	})
}

func (u *stdioUpstream) close() {
	u.die()
	_ = u.stdin.Close()
	if u.kill != nil {
		u.kill()
	}
}

// Call sends one request and awaits its response. The guest-chosen ID is
// replaced with a per-upstream sequence number (ID namespacing).
func (u *stdioUpstream) Call(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	id := u.nextID.Add(1)
	ch := make(chan upstreamReply, 1)
	u.pmu.Lock()
	select {
	case <-u.done:
		u.pmu.Unlock()
		return nil, fmt.Errorf("upstream %s is closed", u.name)
	default:
	}
	u.pending[id] = ch
	u.pmu.Unlock()
	defer func() {
		u.pmu.Lock()
		delete(u.pending, id)
		u.pmu.Unlock()
	}()

	frame, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return nil, err
	}
	u.wmu.Lock()
	_, werr := u.stdin.Write(append(frame, '\n'))
	u.wmu.Unlock()
	if werr != nil {
		return nil, fmt.Errorf("upstream %s write: %w", u.name, werr)
	}

	select {
	case r, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("upstream %s closed mid-call", u.name)
		}
		if r.err != nil {
			return nil, fmt.Errorf("upstream %s error %d: %s", u.name, r.err.Code, r.err.Message)
		}
		return r.result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-u.done:
		return nil, fmt.Errorf("upstream %s closed mid-call", u.name)
	}
}

// Notify sends a notification (no id, no response expected).
func (u *stdioUpstream) Notify(method string, params json.RawMessage) {
	msg := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		msg["params"] = params
	}
	frame, err := json.Marshal(msg)
	if err != nil {
		return
	}
	u.wmu.Lock()
	defer u.wmu.Unlock()
	_, _ = u.stdin.Write(append(frame, '\n'))
}
