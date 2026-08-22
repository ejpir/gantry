package mcpgw

// Manual reproduction harness: spawn the REAL guest helper binary and run
// a full session against it. Skipped unless GANTRY_GUEST_BIN is set.
//
//	GOOS=linux go build -o /tmp/gantry-guest ./cmd/gantry-guest
//	GANTRY_GUEST_BIN=/tmp/gantry-guest go test ./internal/sandbox/mcpgw/ -run TestRealGuest -v

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestRealGuestFS(t *testing.T) {
	bin := os.Getenv("GANTRY_GUEST_BIN")
	if bin == "" {
		t.Skip("set GANTRY_GUEST_BIN to a built gantry-guest binary")
	}
	root := t.TempDir()
	_ = os.WriteFile(root+"/notes.txt", []byte("hello-mcp\n"), 0o644)
	_ = os.Symlink("/etc/passwd", root+"/evil")

	spawn := func(ctx context.Context, argv []string) (io.WriteCloser, io.ReadCloser, func(), error) {
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Stderr = os.Stderr
		stdin, _ := cmd.StdinPipe()
		stdout, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			return nil, nil, nil, err
		}
		return stdin, stdout, func() { _ = cmd.Process.Kill() }, nil
	}
	g, err := New(func(f string, a ...any) { t.Logf("AUDIT: "+f, a...) }, spawn, []Server{{
		Name:  "fs",
		Argv:  []string{bin, "mcp-serve", "filesystem", "--root", root, "--user", os.Getenv("USER")},
		Tools: ToolPolicy{Allow: []string{"read_file", "list_directory"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	lines := runSession(t, g, []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"repro","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fs__read_file","arguments":{"path":"` + root + `/notes.txt"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fs__read_file","arguments":{"path":"` + root + `/evil"}}}`,
	})
	resps := decodeResults(t, lines)
	tools := resps["2"]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tools/list = %v", tools)
	}
	read := resps["3"]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"]
	if read != "hello-mcp\n" {
		t.Fatalf("read_file = %q", read)
	}
	evil := resps["4"]["result"].(map[string]any)
	if evil["isError"] != true {
		t.Fatalf("symlink escape must error: %v", evil)
	}
	text := evil["content"].([]any)[0].(map[string]any)["text"].(string)
	if strings.Contains(text, "root:") {
		t.Fatalf("escape leaked /etc/passwd: %q", text)
	}
}
