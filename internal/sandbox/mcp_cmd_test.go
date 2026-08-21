package sandbox

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/mcpgw"
	"github.com/ejpir/gantry/internal/sandbox/mcpgw/mcpproto"
)

func TestMCPToolsProbe(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		var result any
		switch req["method"] {
		case "initialize":
			result = map[string]any{"protocolVersion": mcpproto.ProtocolVersion,
				"capabilities": map[string]any{}, "serverInfo": map[string]any{"name": "m", "version": "0"}}
		case "tools/list":
			result = map[string]any{"tools": []map[string]any{
				{"name": "visible", "description": "x"}, {"name": "hidden", "description": "y"}}}
		default:
			result = map[string]any{}
		}
		raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": result})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer up.Close()

	gw, err := mcpgw.New(nil, nil, []mcpgw.Server{{
		Name: "mock", URL: up.URL,
		Tools: mcpgw.ToolPolicy{Allow: []string{"*"}, Deny: []string{"hidden"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), mcpproto.SockName)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = gw.Serve(context.Background(), conn) }()
		}
	}()

	byServer, err := mcpToolsProbe(sock)
	if err != nil {
		t.Fatal(err)
	}
	got := byServer["mock"]
	if len(got) != 1 || got[0] != "visible" {
		t.Fatalf("probe = %v — policy-filtered list must hide 'hidden'", byServer)
	}
}

func TestMCPShowConfigNeverPrintsValues(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GANTRY_HOME", home)
	dir := filepath.Join(home, "sb")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := `{"image":"alpine:latest","mcp":true,"mcp_fs_root":"/work","mcpfsUser":"nobody",` +
		`"mcp_remotes":["name=github,url=https://api.githubcopilot.com/mcp/,auth=bearer:GITHUB_TOKEN,allow=read*,deny=admin*"]}`
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	// Capture stdout.
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	rc := mcpShowConfig("sb")
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	if rc != 0 {
		t.Fatalf("rc = %d, out = %s", rc, out)
	}
	s := string(out)
	for _, want := range []string{"fs", "/work", "github", "api.githubcopilot.com", "bearer:GITHUB_TOKEN", "allow=read*", "deny=admin*"} {
		if !strings.Contains(s, want) {
			t.Errorf("config view missing %q:\n%s", want, s)
		}
	}
}
