package mcpworker

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	workerapi "github.com/ejpir/gantry/internal/mcpworker"
	"github.com/ejpir/gantry/internal/sandbox/mcpgw"
)

func TestOrganizationAuthorizationAcrossMCPWorker(t *testing.T) {
	calls := make(chan string, 16)
	worker, err := start([]Server{{Config: workerapi.ServerConfig{Name: "fs", Local: true, Tools: mcpgw.ToolPolicy{Allow: []string{"*"}}}, Spawn: fakeSpawn,
		Authorize: func(_ context.Context, action, tool string) error {
			calls <- action
			if action == "mcp.tools.call" {
				return fmt.Errorf("organization denied")
			}
			return nil
		},
	}}, t.TempDir(), "auto", nil, func(argv, env *[]string) {
		*argv = []string{os.Args[0], "-test.run=^TestMCPWorkerProcessSplitAndRelay$"}
		*env = append(*env, "GANTRY_MCP_WORKER_TEST_HELPER=1")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = worker.Close() }()
	supervisor, guest := net.Pipe()
	defer func() { _ = guest.Close() }()
	done := make(chan error, 1)
	go func() { done <- worker.Serve(context.Background(), supervisor) }()
	_ = guest.SetDeadline(time.Now().Add(10 * time.Second))
	scanner := bufio.NewScanner(guest)
	if _, err := fmt.Fprintln(guest, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); err != nil {
		t.Fatal(err)
	}
	if !scanner.Scan() || !strings.Contains(scanner.Text(), "fs__read_file") {
		t.Fatalf("listing failed: %s %v", scanner.Text(), scanner.Err())
	}
	if _, err := fmt.Fprintln(guest, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fs__read_file"}}`); err != nil {
		t.Fatal(err)
	}
	if !scanner.Scan() || !strings.Contains(scanner.Text(), "unknown or disallowed tool") {
		t.Fatalf("call was not denied: %s %v", scanner.Text(), scanner.Err())
	}
	_ = guest.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not stop")
	}
	found := map[string]bool{}
	for len(calls) > 0 {
		found[<-calls] = true
	}
	if !found["mcp.tools.list"] || !found["mcp.tools.call"] || !found["mcp.connect"] {
		t.Fatalf("scoped checks did not cross worker boundary: %v", found)
	}
}
