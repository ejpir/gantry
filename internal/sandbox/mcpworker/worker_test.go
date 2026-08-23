package mcpworker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	workerapi "github.com/ejpir/gantry/internal/mcpworker"
	"github.com/ejpir/gantry/internal/sandbox/mcpgw"
	"github.com/ejpir/gantry/internal/workerproto"
)

func TestMCPWorkerProcessSplitAndRelay(t *testing.T) {
	if os.Getenv("GANTRY_MCP_WORKER_TEST_HELPER") == "1" {
		os.Exit(workerapi.Cmd())
	}
	const credential = "mcp-process-test-secret"
	var remoteMu sync.Mutex
	var remoteAuth []string
	remote := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		remoteMu.Lock()
		remoteAuth = append(remoteAuth, request.Header.Get("Authorization"))
		remoteMu.Unlock()
		var rpc struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(request.Body).Decode(&rpc)
		if len(rpc.ID) == 0 {
			writer.WriteHeader(http.StatusAccepted)
			return
		}
		var result any = map[string]any{}
		switch rpc.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-06-18"}
		case "tools/list":
			result = map[string]any{"tools": []map[string]any{{"name": "echo_auth"}}}
		case "tools/call":
			result = map[string]any{"content": []map[string]any{{"type": "text", "text": "auth=" + request.Header.Get("Authorization")}}}
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"jsonrpc": "2.0", "id": rpc.ID, "result": result})
	}))
	defer remote.Close()

	var auditMu sync.Mutex
	var audits []string
	worker, err := start([]Server{{
		Config: workerapi.ServerConfig{
			Name: "fs", Local: true,
			Tools: mcpgw.ToolPolicy{Allow: []string{"read_file"}},
		},
		Spawn: fakeSpawn,
	}, {
		Config: workerapi.ServerConfig{
			Name: "remote", URL: remote.URL, Credential: true,
			Tools: mcpgw.ToolPolicy{Allow: []string{"*"}},
		},
		Credential: func() (workerapi.CredentialResponse, error) {
			return workerapi.CredentialResponse{Headers: map[string]string{"Authorization": "Bearer " + credential}}, nil
		},
	}}, t.TempDir(), "auto", func(event mcpgw.Event) {
		auditMu.Lock()
		audits = append(audits, event.String())
		auditMu.Unlock()
	}, func(argv, environment *[]string) {
		*argv = []string{os.Args[0], "-test.run=^TestMCPWorkerProcessSplitAndRelay$"}
		*environment = append(*environment, "GANTRY_MCP_WORKER_TEST_HELPER=1")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := worker.Close(); err != nil {
			t.Errorf("close MCP worker: %v", err)
		}
	}()
	if report := worker.ConfinementReport(); report == nil || !report.Applied || report.Mode != "auto" {
		t.Fatalf("confinement report = %+v", report)
	}

	supervisor, guest := net.Pipe()
	serveDone := make(chan error, 1)
	go func() { serveDone <- worker.Serve(context.Background(), supervisor) }()
	for _, request := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"remote__echo_auth","arguments":{}}}`,
	} {
		if _, err := fmt.Fprintln(guest, request); err != nil {
			t.Fatal(err)
		}
	}
	_ = guest.SetReadDeadline(time.Now().Add(10 * time.Second))
	scanner := bufio.NewScanner(guest)
	foundLocal, foundRemote, foundRedacted := false, false, false
	var responses []string
	for scanner.Scan() {
		line := scanner.Text()
		responses = append(responses, line)
		foundLocal = foundLocal || strings.Contains(line, "fs__read_file")
		foundRemote = foundRemote || strings.Contains(line, "remote__echo_auth")
		if strings.Contains(line, `"id":3`) {
			if strings.Contains(line, credential) {
				t.Fatalf("split gateway leaked credential: %s", line)
			}
			foundRedacted = strings.Contains(line, "*")
		}
		if foundLocal && foundRemote && foundRedacted {
			break
		}
	}
	if !foundLocal || !foundRemote || !foundRedacted {
		t.Fatalf("split gateway responses = %v (scan error %v)", responses, scanner.Err())
	}
	_ = guest.Close()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guest relay did not close")
	}
	auditMu.Lock()
	joined := strings.Join(audits, "\n")
	auditMu.Unlock()
	if !strings.Contains(joined, "mcp: session open") || !strings.Contains(joined, "upstream fs started") ||
		!strings.Contains(joined, "upstream remote started") {
		t.Fatalf("structured worker audits = %q", joined)
	}
	remoteMu.Lock()
	seenAuth := append([]string(nil), remoteAuth...)
	remoteMu.Unlock()
	if !containsString(seenAuth, "Bearer "+credential) {
		t.Fatalf("remote credential not delivered: %v", seenAuth)
	}
}

func TestSupervisorRejectsUnissuedAndRevokedSessionCapabilities(t *testing.T) {
	worker := &Worker{
		servers: map[string]Server{
			"remote": {
				Config: workerapi.ServerConfig{Name: "remote", URL: "https://example.com/mcp", Credential: true},
				Credential: func() (workerapi.CredentialResponse, error) {
					return workerapi.CredentialResponse{Headers: map[string]string{"Authorization": "Bearer secret"}}, nil
				},
			},
		},
		sessionCapabilities: make(map[string]struct{}),
	}
	credentialRequest := func(capability string) workerproto.Request {
		body, err := json.Marshal(workerapi.CredentialRequest{Server: "remote", Session: capability})
		if err != nil {
			t.Fatal(err)
		}
		return workerproto.Request{Op: workerapi.OpCredential, Body: body}
	}

	forged := "0123456789abcdef0123456789abcdef"
	if _, err := worker.credential(credentialRequest(forged)); err == nil {
		t.Fatal("unissued session capability released a credential")
	}
	if err := worker.openWorkerStream(context.Background(), workerapi.OpenRequest{
		Kind: workerapi.StreamRemote, Server: "remote", Session: forged,
	}, nil); err == nil {
		t.Fatal("unissued session capability opened a remote stream")
	}

	capability, err := worker.registerSessionCapability()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.credential(credentialRequest(capability)); err != nil {
		t.Fatalf("active supervisor capability rejected: %v", err)
	}
	worker.revokeSessionCapability(capability)
	if _, err := worker.credential(credentialRequest(capability)); err == nil {
		t.Fatal("revoked session capability released a credential")
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func fakeSpawn(ctx context.Context) (io.WriteCloser, io.ReadCloser, func(), error) {
	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = stdoutWriter.Close() }()
		scanner := bufio.NewScanner(stdinReader)
		for scanner.Scan() {
			var request struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			if json.Unmarshal(scanner.Bytes(), &request) != nil || len(request.ID) == 0 {
				continue
			}
			var result any = map[string]any{}
			switch request.Method {
			case "initialize":
				result = map[string]any{"protocolVersion": "2025-06-18"}
			case "tools/list":
				result = map[string]any{"tools": []map[string]any{{"name": "read_file"}}}
			}
			response, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
			_, _ = stdoutWriter.Write(append(response, '\n'))
		}
	}()
	kill := func() {
		_ = stdinReader.Close()
		_ = stdoutReader.Close()
	}
	go func() {
		select {
		case <-ctx.Done():
			kill()
		case <-done:
		}
	}()
	return stdinWriter, stdoutReader, kill, nil
}
