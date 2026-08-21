package mcpgw

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// mockRemote is a test MCP streamable-HTTP server recording the headers
// it receives (credential injection must reach the upstream, never the
// guest).
type mockRemote struct {
	mu       sync.Mutex
	authSeen []string
	sse      bool // answer with text/event-stream instead of JSON
	session  string
}

func (m *mockRemote) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.authSeen = append(m.authSeen, r.Header.Get("Authorization"))
		m.mu.Unlock()
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params map[string]any  `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.ID == nil { // notification
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if m.session != "" {
			w.Header().Set("Mcp-Session-Id", m.session)
		}
		var result any
		switch req.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": protocolVersion, "capabilities": map[string]any{}, "serverInfo": map[string]any{"name": "mock", "version": "0"}}
		case "tools/list":
			result = map[string]any{"tools": []map[string]any{{"name": "echo_auth", "description": "echoes the Authorization header"}, {"name": "leak", "description": "returns a secret"}}}
		case "tools/call":
			name, _ := req.Params["name"].(string)
			switch name {
			case "echo_auth":
				m.mu.Lock()
				auth := m.authSeen[len(m.authSeen)-1]
				m.mu.Unlock()
				result = map[string]any{"content": []map[string]any{{"type": "text", "text": "auth=" + auth}}}
			case "leak":
				result = map[string]any{"content": []map[string]any{{"type": "text", "text": "the token is t12-secret-token"}}}
			default:
				result = map[string]any{"content": []map[string]any{{"type": "text", "text": "unknown"}}, "isError": true}
			}
		default:
			result = map[string]any{}
		}
		raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(req.ID), "result": result})
		if m.sse {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", raw)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}
}

func startMock(t *testing.T, m *mockRemote) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestHTTPUpstreamInjectAndRedact(t *testing.T) {
	mock := &mockRemote{}
	srv := startMock(t, mock)
	g, err := New(nil, nil, []Server{{
		Name:    "mock",
		URL:     srv.URL,
		Headers: map[string]string{"Authorization": "Bearer t12-secret-token"},
		Tools:   ToolPolicy{Allow: []string{"*"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	lines := runSession(t, g, []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mock__echo_auth","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"mock__leak","arguments":{}}}`,
	})
	resps := decodeResults(t, lines)
	tools := resps["2"]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tools/list = %v", tools)
	}
	// The injected credential reached the upstream...
	mock.mu.Lock()
	sawBearer := false
	for _, a := range mock.authSeen {
		if a == "Bearer t12-secret-token" {
			sawBearer = true
		}
	}
	mock.mu.Unlock()
	if !sawBearer {
		t.Fatalf("upstream never saw the injected credential: %v", mock.authSeen)
	}
	// ...and is redacted from anything forwarded back to the guest, even
	// when the upstream reflects it (echo_auth) or a response body
	// contains it verbatim (leak).
	for _, id := range []string{"3", "4"} {
		text := resps[id]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
		if strings.Contains(text, "t12-secret-token") {
			t.Fatalf("id %s leaked the credential to the guest: %q", id, text)
		}
		if !strings.Contains(text, redactionPlaceholder) {
			t.Fatalf("id %s: expected redaction placeholder, got %q", id, text)
		}
	}
}

func TestHTTPUpstreamSSEAndSessionID(t *testing.T) {
	mock := &mockRemote{sse: true, session: "sess-abc"}
	srv := startMock(t, mock)
	g, err := New(nil, nil, []Server{{
		Name: "mock", URL: srv.URL, Tools: ToolPolicy{Allow: []string{"*"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	lines := runSession(t, g, []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	})
	resps := decodeResults(t, lines)
	tools := resps["2"]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("SSE tools/list = %v", tools)
	}
}

func TestHTTPUpstreamRedirectRefusedWithCredentials(t *testing.T) {
	// A redirecting endpoint behind a credentialed upstream: the client
	// must hard-error, never follow.
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/stolen", http.StatusFound)
	}))
	defer redir.Close()
	u, err := startHTTPUpstream(context.Background(), nil, Server{
		Name:    "redir",
		URL:     redir.URL,
		Headers: map[string]string{"Authorization": "Bearer x"},
	})
	if err == nil {
		u.close()
		t.Fatal("redirect on a credentialed upstream must fail the handshake")
	}
	if !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("error = %v, want redirect refused", err)
	}
}

func TestValidateRemoteURLAndDialGuard(t *testing.T) {
	for _, tc := range []struct {
		url      string
		wantErr  string // "" = ok
		wantPriv bool
	}{
		{"https://api.githubcopilot.com/mcp/", "", false},
		{"http://127.0.0.1:18998/mcp", "", true},
		{"http://localhost:8080/x", "", true},
		{"https://[::1]:8443/mcp", "", true},
		{"http://example.com/mcp", "plain HTTP", false},
		{"ftp://example.com/", "scheme", false},
		{"https://user:pw@example.com/mcp", "credentials in the URL", false},
		{"https://169.254.169.254/latest/meta-data", "non-public", false},
		{"https://192.168.1.1/mcp", "non-public", false},
		{"https://10.0.0.5/mcp", "non-public", false},
	} {
		priv, err := ValidateRemoteURL(tc.url)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%s: %v, want ok", tc.url, err)
			}
			if priv != tc.wantPriv {
				t.Errorf("%s: allowPrivate=%v, want %v", tc.url, priv, tc.wantPriv)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: err = %v, want substring %q", tc.url, err, tc.wantErr)
		}
	}
	// The dial guard vetoes a hostname that RESOLVES to a non-public
	// address even when the URL itself looked public-shaped (rebinding).
	tr := pinnedTransport(false)
	conn, err := tr.DialContext(context.Background(), "tcp", "localhost:443")
	if err == nil {
		_ = conn.Close()
		t.Fatal("localhost must be refused without allowPrivate")
	}
	if !strings.Contains(err.Error(), "ssrf") {
		t.Fatalf("err = %v, want ssrf refusal", err)
	}
	tr = pinnedTransport(true)
	conn, err = tr.DialContext(context.Background(), "tcp", "localhost:1")
	if err != nil && strings.Contains(err.Error(), "ssrf") {
		t.Fatalf("loopback with allowPrivate must pass the guard (dial may fail): %v", err)
	}
	if conn != nil {
		_ = conn.Close()
	}
}
