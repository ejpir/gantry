package mcpgw

import (
	"bytes"
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
		reflectErr := func() bool {
			name := ""
			if req.Method == "tools/call" {
				name, _ = req.Params["name"].(string)
			}
			switch name {
			case "err_http": // reflect the credential in an HTTP error body
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = fmt.Fprintf(w, `{"detail":"token %s was rejected"}`, r.Header.Get("Authorization"))
				return true
			case "err_rpc": // reflect it in a JSON-RPC error message
				w.Header().Set("Content-Type", "application/json")
				raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(req.ID),
					"error": map[string]any{"code": -32000, "message": "bad token " + r.Header.Get("Authorization")}})
				_, _ = w.Write(raw)
				return true
			}
			return false
		}
		if reflectErr() {
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
			case "escape_auth":
				m.mu.Lock()
				auth := m.authSeen[len(m.authSeen)-1]
				m.mu.Unlock()
				var escaped strings.Builder
				for _, ch := range "auth=" + auth {
					_, _ = fmt.Fprintf(&escaped, `\u%04x`, ch)
				}
				result = json.RawMessage(`{"content":[{"type":"text","text":"` + escaped.String() + `"}]}`)
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

func TestHTTPUpstreamRedactsJSONEscapedCredential(t *testing.T) {
	const token = "t12-secret-token"
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sse=%t", sse), func(t *testing.T) {
			mock := &mockRemote{sse: sse}
			srv := startMock(t, mock)
			g, err := New(nil, nil, []Server{{
				Name:    "mock",
				URL:     srv.URL,
				Headers: map[string]string{"Authorization": "Bearer " + token},
				Tools:   ToolPolicy{Allow: []string{"*"}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			lines := runSession(t, g, []string{
				`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mock__escape_auth","arguments":{}}}`,
			})
			resps := decodeResults(t, lines)
			text := resps["1"]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
			if strings.Contains(text, token) {
				t.Fatalf("JSON-escaped credential reached the guest: %q", text)
			}
		})
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
		if !strings.Contains(text, "*") && !strings.Contains(text, redactionPlaceholder) {
			t.Fatalf("id %s: expected a redaction marker, got %q", id, text)
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

func TestHTTPUpstreamRedirectRefusedWithoutCredentials(t *testing.T) {
	// Loopback is a narrowly scoped development exception. A redirect must
	// not turn it into permission to dial metadata/private addresses.
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer redir.Close()
	u, err := startHTTPUpstream(context.Background(), nil, Server{Name: "redir", URL: redir.URL})
	if err == nil {
		u.close()
		t.Fatal("uncredentialed MCP redirect must be refused")
	}
	if !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("error = %v, want redirect refusal", err)
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
		{"https://192.0.2.1/mcp", "non-public", false},
		{"https://255.255.255.255/mcp", "non-public", false},
		{"https://[2001:db8::1]/mcp", "non-public", false},
		{"https://[64:ff9b::a9fe:a9fe]/mcp", "non-public", false},
		{"https://8.8.8.8/mcp", "", false},
		{"https://[2606:4700:4700::1111]/mcp", "", false},
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

func TestHTTPErrorPathsAreRedacted(t *testing.T) {
	var logs []string
	logf := func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	srv := startMock(t, &mockRemote{})
	g, err := New(logf, nil, []Server{{
		Name:    "mock",
		URL:     srv.URL,
		Headers: map[string]string{"Authorization": "Bearer t12-secret-token"},
		Tools:   ToolPolicy{Allow: []string{"err_*"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	lines := runSession(t, g, []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mock__err_http","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mock__err_rpc","arguments":{}}}`,
	})
	resps := decodeResults(t, lines)
	// Guest side: generic failure, never the upstream's error text.
	for _, id := range []string{"2", "3"} {
		raw, _ := json.Marshal(resps[id])
		if bytes.Contains(raw, []byte("t12-secret-token")) {
			t.Fatalf("id %s leaked the credential to the guest: %s", id, raw)
		}
		if !bytes.Contains(raw, []byte("upstream call failed")) {
			t.Fatalf("id %s should get the generic failure: %s", id, raw)
		}
	}
	// Host audit contains decision metadata only. Even redacted upstream
	// payload previews do not belong in the custody trail.
	var errLines []string
	for _, l := range logs {
		if strings.Contains(l, "upstream error") {
			errLines = append(errLines, l)
		}
	}
	if len(errLines) != 2 {
		t.Fatalf("expected 2 audited upstream errors, got %v", logs)
	}
	for _, l := range errLines {
		if strings.Contains(l, "t12-secret-token") || strings.Contains(l, "token ") || strings.Contains(l, "bad token") {
			t.Fatalf("audit line carried upstream payload: %s", l)
		}
	}
}

func TestHTTPUpstreamRejectsMissingResultAndError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if req.Method == "initialize" {
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":%q}}`, req.ID, protocolVersion)
			return
		}
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s}`, req.ID)
	}))
	defer srv.Close()
	u, err := startHTTPUpstream(context.Background(), nil, Server{Name: "bad", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer u.close()
	if _, err := u.Call(context.Background(), "tools/call", json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("missing result/error response was accepted: %v", err)
	}
}

func TestAuditRemoteOriginOmitsPotentialCredentialMaterial(t *testing.T) {
	got := AuditRemoteOrigin("https://api.example.test:8443/mcp/customer-secret?access_token=query-secret")
	if got != "https://api.example.test:8443" {
		t.Fatalf("audit origin = %q", got)
	}
}
