package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// serveFSOnce feeds one JSON-RPC line through the filesystem server and
// returns the decoded response.
func serveFSOnce(t *testing.T, jail *os.Root, request string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := serveFS(jail, strings.NewReader(request+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("response is not JSON: %q", out.String())
	}
	return resp
}

func testJail(t *testing.T) (*os.Root, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hello-mcp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	jail, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jail.Close() })
	return jail, dir
}

func toolResultText(t *testing.T, resp map[string]any) (text string, isErr bool) {
	t.Helper()
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in %v", resp)
	}
	content := result["content"].([]any)
	text = content[0].(map[string]any)["text"].(string)
	isErr, _ = result["isError"].(bool)
	return text, isErr
}

func TestFSReadFile(t *testing.T) {
	jail, _ := testJail(t)
	resp := serveFSOnce(t, jail, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"notes.txt"}}}`)
	text, isErr := toolResultText(t, resp)
	if isErr || text != "hello-mcp\n" {
		t.Fatalf("read_file = %q (isError %v)", text, isErr)
	}
	// Absolute-looking paths resolve inside the jail too.
	resp = serveFSOnce(t, jail, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/notes.txt"}}}`)
	if text, isErr := toolResultText(t, resp); isErr || text != "hello-mcp\n" {
		t.Fatalf("read_file absolute = %q (isError %v)", text, isErr)
	}
}

func TestFSSymlinkEscapeDenied(t *testing.T) {
	jail, dir := testJail(t)
	// A symlink inside the jail pointing outside it.
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("TOP-SECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "evil-link")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"evil-link", "../" + filepath.Base(dir) + "/../", ".."} {
		resp := serveFSOnce(t, jail, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":`+jsonStr(p)+`}}}`)
		text, isErr := toolResultText(t, resp)
		if !isErr {
			t.Fatalf("escape via %q must fail, got %q", p, text)
		}
		if strings.Contains(text, "TOP-SECRET") {
			t.Fatalf("escape via %q leaked host file contents", p)
		}
	}
}

func TestFSBinaryAndSizeCap(t *testing.T) {
	jail, dir := testJail(t)
	if err := os.WriteFile(filepath.Join(dir, "bin.dat"), []byte{'A', 0, 'B'}, 0o644); err != nil {
		t.Fatal(err)
	}
	resp := serveFSOnce(t, jail, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"bin.dat"}}}`)
	if text, isErr := toolResultText(t, resp); !isErr || !strings.Contains(text, "binary") {
		t.Fatalf("binary file must be refused, got %q (isError %v)", text, isErr)
	}
	big := strings.Repeat("x", fsMaxFileBytes+10)
	if err := os.WriteFile(filepath.Join(dir, "big.txt"), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	resp = serveFSOnce(t, jail, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"big.txt"}}}`)
	if text, isErr := toolResultText(t, resp); !isErr || !strings.Contains(text, "exceeds") {
		t.Fatalf("oversize file must be refused, got %.40q (isError %v)", text, isErr)
	}
}

func TestFSListDirAndHandshake(t *testing.T) {
	jail, _ := testJail(t)
	resp := serveFSOnce(t, jail, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_directory","arguments":{"path":"."}}}`)
	text, isErr := toolResultText(t, resp)
	if isErr || !strings.Contains(text, "notes.txt (file)") || !strings.Contains(text, "sub (dir)") {
		t.Fatalf("list_directory = %q (isError %v)", text, isErr)
	}

	resp = serveFSOnce(t, jail, `{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}`)
	init := resp["result"].(map[string]any)
	if init["protocolVersion"] != fsProtocolVer {
		t.Fatalf("protocolVersion = %v", init["protocolVersion"])
	}
	resp = serveFSOnce(t, jail, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	tools := resp["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tools/list = %v", tools)
	}
	resp = serveFSOnce(t, jail, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_everything","arguments":{}}}`)
	if text, isErr := toolResultText(t, resp); !isErr || !strings.Contains(text, "unknown tool") {
		t.Fatalf("unknown tool must be an isError result, got %q", text)
	}
	// Notifications get no response.
	var out bytes.Buffer
	if err := serveFS(jail, strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("notification produced output: %q", out.String())
	}
}

// jsonStr renders a Go string as a JSON string literal.
func jsonStr(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

func TestRelPath(t *testing.T) {
	for in, want := range map[string]string{
		"":            ".",
		"/etc/passwd": "etc/passwd",
		"notes.txt":   "notes.txt",
		"./sub/../x":  "x",
	} {
		if got := relPath(in); got != want {
			t.Errorf("relPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDropToUserRefusesRoot(t *testing.T) {
	if err := dropToUser(""); err == nil {
		t.Error("empty user must be refused")
	}
	if err := dropToUser("root"); err == nil {
		t.Error("root must be refused")
	}
	if err := dropToUser("0"); err == nil {
		t.Error("uid 0 must be refused")
	}
	if err := dropToUser("definitely-not-a-user-42"); err == nil {
		t.Error("unknown user must be refused")
	}
}
