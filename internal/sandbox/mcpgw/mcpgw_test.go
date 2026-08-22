package mcpgw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeServer is an in-process MCP stdio server used as a spawned
// upstream. It records every request line it receives so tests can
// assert what the gateway forwarded (and with which IDs).
type fakeServer struct {
	mu      sync.Mutex
	lines   []string
	respond func(method string, params json.RawMessage) (result any, errMsg string)
}

func (f *fakeServer) record(line string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lines = append(f.lines, line)
}

func (f *fakeServer) sawCall(tool string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.lines {
		if strings.Contains(l, `"tools/call"`) && strings.Contains(l, tool) {
			return true
		}
	}
	return false
}

// fakeSpawn wires a fakeServer to io.Pipes and returns the SpawnFunc.
func fakeSpawn(t *testing.T, f *fakeServer) SpawnFunc {
	t.Helper()
	return func(ctx context.Context, argv []string) (io.WriteCloser, io.ReadCloser, func(), error) {
		stdinR, stdinW := io.Pipe()
		stdoutR, stdoutW := io.Pipe()
		go func() {
			defer func() { _ = stdoutW.Close() }()
			for {
				line, err := readOneLine(stdinR)
				if err != nil {
					return
				}
				f.record(line)
				var req rpcRequest
				if err := json.Unmarshal([]byte(line), &req); err != nil || len(req.ID) == 0 {
					continue
				}
				var resp map[string]any
				switch req.Method {
				case "initialize":
					resp = map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(req.ID), "result": map[string]any{"protocolVersion": protocolVersion}}
				default:
					result, errMsg := f.respond(req.Method, req.Params)
					if errMsg != "" {
						resp = map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(req.ID), "error": map[string]any{"code": -32000, "message": errMsg}}
					} else {
						resp = map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(req.ID), "result": result}
					}
				}
				raw, _ := json.Marshal(resp)
				if _, err := stdoutW.Write(append(raw, '\n')); err != nil {
					return
				}
			}
		}()
		kill := func() {
			_ = stdinR.Close()
			_ = stdoutR.Close()
		}
		return stdinW, stdoutR, kill, nil
	}
}

func readOneLine(r io.Reader) (string, error) {
	var b strings.Builder
	buf := make([]byte, 256)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := string(buf[:n])
			if i := strings.IndexByte(chunk, '\n'); i >= 0 {
				b.WriteString(chunk[:i])
				return b.String(), nil
			}
			b.WriteString(chunk)
		}
		if err != nil {
			return "", err
		}
	}
}

// syncBuf is a non-blocking response sink: Serve must never block
// writing while the test is still sending requests (an io.Pipe on both
// ends deadlocks exactly that way).
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	raw := b.buf.String()
	var out []string
	for _, l := range strings.Split(raw, "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// runSession drives one gateway session over an in-memory pipe and
// returns the transcript of response lines. Dispatch is concurrent, so
// the transcript order is unspecified (decodeResults keys by id).
func runSession(t *testing.T, g *Gateway, requests []string) []string {
	t.Helper()
	inR, inW := io.Pipe()
	out := &syncBuf{}
	done := make(chan error, 1)
	go func() { done <- g.Serve(context.Background(), rwc{inR, out}) }()

	want := 0
	for _, r := range requests {
		trimmed := strings.TrimSpace(r)
		if strings.HasPrefix(trimmed, "[") {
			want++ // a rejected batch still gets one error response
			continue
		}
		var probe map[string]any
		if json.Unmarshal([]byte(trimmed), &probe) == nil {
			if _, hasID := probe["id"]; hasID {
				want++
			}
		}
	}
	// Writes must not block behind responses: feed the pipe from a
	// goroutine (the input side stays a real io.Pipe on purpose, so the
	// session sees a stream, not a buffer).
	go func() {
		for _, req := range requests {
			if _, err := inW.Write([]byte(req + "\n")); err != nil {
				return
			}
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		lines := out.lines()
		if len(lines) >= want {
			_ = inW.Close()
			<-done
			return lines
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %d responses, want %d: %v", len(lines), want, lines)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type rwc struct {
	io.Reader
	io.Writer
}

func (r rwc) Close() error { return nil }

// decodeResults keys responses by their (numeric) id: dispatch is
// concurrent, so response order is deliberately not guaranteed.
func decodeResults(t *testing.T, lines []string) map[string]map[string]any {
	t.Helper()
	out := make(map[string]map[string]any, len(lines))
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("response is not JSON: %q", l)
		}
		out[string(mustJSON(m["id"]))] = m
	}
	return out
}

var echoToolsResult = map[string]any{"tools": []map[string]any{
	{"name": "echo", "description": "echoes args"},
	{"name": "hidden_admin", "description": "policy-hidden"},
	{"name": "github-authorize", "description": "rebinds auth"},
}}

func echoRespond(method string, params json.RawMessage) (any, string) {
	switch method {
	case "tools/list":
		return echoToolsResult, ""
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		_ = json.Unmarshal(params, &p)
		return map[string]any{"content": []map[string]any{
			{"type": "text", "text": fmt.Sprintf("echoed:%s:%v", p.Name, p.Arguments["msg"])},
		}}, ""
	}
	return nil, "unsupported"
}

func testGateway(t *testing.T, f *fakeServer) *Gateway {
	t.Helper()
	f.respond = echoRespond
	g, err := New(nil, fakeSpawn(t, f), []Server{{
		Name:  "fs",
		Argv:  []string{"/bin/fake-fs"},
		Tools: ToolPolicy{Allow: []string{"echo", "hidden_*"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGatewaySessionEndToEnd(t *testing.T) {
	f := &fakeServer{}
	g := testGateway(t, f)
	lines := runSession(t, g, []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"fs__echo","arguments":{"msg":"hi"}}}`,
	})
	resps := decodeResults(t, lines)

	// initialize
	init := resps["1"]["result"].(map[string]any)
	if init["protocolVersion"] != protocolVersion {
		t.Fatalf("protocolVersion = %v", init["protocolVersion"])
	}
	// tools/list: namespaced, auth tool hidden.
	tools := resps["2"]["result"].(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, tool := range tools {
		names[tool.(map[string]any)["name"].(string)] = true
	}
	if !names["fs__echo"] || !names["fs__hidden_admin"] {
		t.Fatalf("expected fs__echo and fs__hidden_admin, got %v", names)
	}
	if names["fs__github-authorize"] {
		t.Fatal("authorize tool must never be exposed to the agent")
	}
	// tools/call: routed, and the response carries the CLIENT's id (99)
	// even though the upstream saw a gateway-generated one.
	call := resps["99"]
	if string(mustJSON(call["id"])) != "99" {
		t.Fatalf("response id = %s, want client id 99", mustJSON(call["id"]))
	}
	text := call["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"]
	if text != "echoed:echo:hi" {
		t.Fatalf("call result = %v", text)
	}
	// ID namespacing: the upstream never saw id 99.
	for _, l := range f.lines {
		if strings.Contains(l, `"tools/call"`) && strings.Contains(l, `"id":99`) {
			t.Fatalf("guest-chosen id leaked upstream: %s", l)
		}
	}
}

func mustJSON(v any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}

func TestGatewayPolicyDenyAndUnknown(t *testing.T) {
	f := &fakeServer{}
	g := testGateway(t, f)
	lines := runSession(t, g, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fs__github-authorize","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fs__nonexistent","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nosuchserver__echo","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"resources/list"}`,
	})
	resps := decodeResults(t, lines)
	for _, id := range []string{"1", "2", "3", "4"} {
		resp := resps[id]
		e, ok := resp["error"].(map[string]any)
		if !ok {
			t.Fatalf("response %s: want error, got %v", id, resp)
		}
		if id != "4" && !strings.Contains(e["message"].(string), "unknown or disallowed") {
			t.Fatalf("response %s: %v", id, e)
		}
	}
	// Denied calls must never reach the upstream.
	if f.sawCall("github-authorize") || f.sawCall("nonexistent") {
		t.Fatalf("denied call reached the upstream: %v", f.lines)
	}
}

func TestGatewayRejectsGarbage(t *testing.T) {
	f := &fakeServer{}
	g := testGateway(t, f)
	lines := runSession(t, g, []string{
		`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, // batch: rejected
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
	})
	resps := decodeResults(t, lines)
	if resps["null"]["error"] == nil { // batch reject carries a null id
		t.Fatalf("batch must be rejected: %v", resps)
	}
	if resps["2"]["result"] == nil {
		t.Fatalf("ping after reject must still work: %v", resps["2"])
	}
}

func TestGatewayRedactsUpstreamResults(t *testing.T) {
	f := &fakeServer{}
	f.respond = func(method string, params json.RawMessage) (any, string) {
		if method == "tools/list" {
			return map[string]any{"tools": []map[string]any{{"name": "leaky"}}}, ""
		}
		// A reflecting/compromised server returns the token it was given.
		return map[string]any{"content": []map[string]any{
			{"type": "text", "text": "the header was hunter2 ok?"}}}, ""
	}
	g, err := New(nil, fakeSpawn(t, f), []Server{{
		Name:   "evil",
		Argv:   []string{"/bin/evil"},
		Tools:  ToolPolicy{Allow: []string{"*"}},
		Redact: [][]byte{[]byte("hunter2")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	lines := runSession(t, g, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"evil__leaky","arguments":{}}}`,
	})
	if strings.Contains(lines[0], "hunter2") {
		t.Fatalf("credential material reached the guest: %s", lines[0])
	}
	if !strings.Contains(lines[0], "*") && !strings.Contains(lines[0], redactionPlaceholder) {
		t.Fatalf("redaction marker missing: %s", lines[0])
	}
}

func TestRedactBytesDoesNotRescanOrGrow(t *testing.T) {
	// "A" occurs in the human-readable placeholder. The old replacement
	// loop kept finding its own output forever.
	got := redactBytes([]byte("A-A"), [][]byte{[]byte("A")})
	if bytes.Contains(got, []byte("A")) {
		t.Fatalf("short secret survived redaction: %q", got)
	}
	if len(got) > len("A-A") {
		t.Fatalf("redaction grew a bounded frame: %d > %d", len(got), len("A-A"))
	}
}

func TestGatewayCapsConcurrentSessions(t *testing.T) {
	g, err := New(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	clients := make([]net.Conn, 0, maxSessions)
	done := make([]chan error, 0, maxSessions)
	for i := 0; i < maxSessions; i++ {
		client, server := net.Pipe()
		clients = append(clients, client)
		result := make(chan error, 1)
		done = append(done, result)
		go func() { result <- g.Serve(context.Background(), server) }()
	}
	deadline := time.Now().Add(time.Second)
	for len(g.sessions) != maxSessions && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(g.sessions); got != maxSessions {
		t.Fatalf("active sessions = %d, want %d", got, maxSessions)
	}
	overflowClient, overflowServer := net.Pipe()
	if err := g.Serve(context.Background(), overflowServer); err == nil || !strings.Contains(err.Error(), "too many sessions") {
		t.Fatalf("overflow Serve error = %v", err)
	}
	_ = overflowClient.Close()
	for _, client := range clients {
		_ = client.Close()
	}
	for _, result := range done {
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Fatal("session did not unwind")
		}
	}
}

func TestToolExposedRules(t *testing.T) {
	srv := Server{Name: "fs", Tools: ToolPolicy{Allow: []string{"read_*", "list_*"}, Deny: []string{"read_secret"}}}
	for tool, want := range map[string]bool{
		"read_file":      true,
		"list_directory": true,
		"read_secret":    false, // deny wins
		"write_file":     false, // not in allow
		"x-authorize":    false, // auth rule
		"x-revoke-auth":  false,
		"foo/bar":        false,
	} {
		if got := toolExposed(srv, tool); got != want {
			t.Errorf("toolExposed(%q) = %v, want %v", tool, got, want)
		}
	}
	// Default deny: empty allow exposes nothing.
	bare := Server{Name: "bare"}
	if toolExposed(bare, "anything") {
		t.Error("empty allow list must expose no tools")
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New(nil, nil, []Server{{Name: "a__b"}}); err == nil {
		t.Error("server name containing __ must be rejected")
	}
	if _, err := New(nil, nil, []Server{{Name: "x"}, {Name: "x"}}); err == nil {
		t.Error("duplicate server names must be rejected")
	}
	if _, err := New(nil, nil, []Server{{Name: "x", Tools: ToolPolicy{Allow: []string{"[bad"}}}}); err == nil {
		t.Error("bad glob must be rejected")
	}
}
