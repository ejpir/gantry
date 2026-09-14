package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/policy"
)

func TestFixturesExerciseSignatureAndProfileGates(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f, err := newFixtures(root, 18080, 18081)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, key, profile, reason string }{
		{f.good, f.publicKey, "dev", ""},
		{f.tampered, f.publicKey, "dev", "digest mismatch"},
		{f.unsigned, f.publicKey, "dev", "must contain signed data.json"},
		{f.good, f.wrongKey, "dev", "verify organization bundle"},
		{f.good, f.publicKey, "other", "does not exist"},
		{f.expired, f.publicKey, "dev", "expired"},
	} {
		_, err := policy.ReadConfig(tc.path, tc.key, tc.profile)
		if tc.reason == "" {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil || !strings.Contains(err.Error(), tc.reason) {
			t.Errorf("%s: wanted %q, got %v", tc.path, tc.reason, err)
		}
	}
	config, err := policy.ReadConfig(f.good, f.publicKey, "dev")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		action   string
		resource policy.Resource
		allow    bool
	}{
		{policy.NetworkConnect, policy.Resource{IP: "192.168.127.254", Protocol: "tcp", Port: 18080}, true},
		{policy.NetworkConnect, policy.Resource{IP: "192.168.127.254", Protocol: "tcp", Port: 18081}, false},
		{policy.NetworkConnect, policy.Resource{IP: "127.0.0.1", Protocol: "tcp", Port: 18081}, false},
		{policy.NetworkResolve, policy.Resource{Host: "gateway.containers.internal"}, true},
		{policy.NetworkResolve, policy.Resource{Host: "host.containers.internal"}, false},
		{policy.NetworkResolve, policy.Resource{Host: "git.denied.test"}, true}, // credential denial must not just be a DNS denial
		{policy.CredentialUse, policy.Resource{Host: "git.denied.test"}, false},
		{policy.MCPList, policy.Resource{Server: "mock", Tool: "listed"}, true},
		{policy.MCPCall, policy.Resource{Server: "mock", Tool: "listed"}, false},
		{policy.MCPList, policy.Resource{Server: "mock", Tool: "hidden"}, false},
		{policy.MCPCall, policy.Resource{Server: "blocked", Tool: "read"}, true}, // blocked upstream must reach the dial gate
		{policy.MountRead, policy.Resource{Path: f.allowed}, true},
		{policy.MountWrite, policy.Resource{Path: f.allowed}, false},
		{policy.MountRead, policy.Resource{Path: f.forbidden}, false},
	} {
		d := engine.Evaluate(context.Background(), tc.action, tc.resource)
		if (d.Effect == "allow") != tc.allow {
			t.Errorf("fixture does not isolate %s %+v: %+v", tc.action, tc.resource, d)
		}
	}
}

func TestCommandBufferIsBounded(t *testing.T) {
	var output commandBuffer
	data := bytes.Repeat([]byte("x"), maxOutput+100)
	if n, err := output.Write(data); err != nil || n != len(data) {
		t.Fatalf("write=%d,%v", n, err)
	}
	if output.Len() != maxOutput || !output.truncated {
		t.Fatal("command output was not bounded")
	}
	if _, err := output.Write([]byte("more")); err != nil || output.Len() != maxOutput {
		t.Fatal("overflow write grew buffer")
	}
}

func TestEnvironmentAndStateAreIsolated(t *testing.T) {
	actual := environment([]string{"GANTRY_HOME=old", "gantry_home=also-old", "KEEP=value"}, map[string]string{"GANTRY_HOME": "private"})
	if strings.Join(actual, ";") != "KEEP=value;GANTRY_HOME=private" {
		t.Fatalf("unexpected environment: %v", actual)
	}
	text := "NAME STATE PID\npol-expiry-other running 1\npol-expiry stopped -\n"
	if sandboxState(text, "pol-expiry") != "stopped" || sandboxState(text, "missing") != "" {
		t.Fatal("state inspection did not match exact sandbox")
	}
}

func TestHarnessHelperProcess(t *testing.T) {
	if os.Getenv("GANTRY_POLICY_E2E_HELPER") != "1" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "deny":
		fmt.Println("OPA-DENIED")
		os.Exit(23)
	case "large":
		fmt.Print(strings.Repeat("x", maxOutput+1))
		os.Exit(0)
	case "hang":
		time.Sleep(time.Minute)
		os.Exit(0)
	default:
		fmt.Println(os.Getenv("OPA_ALLOW"))
		os.Exit(0)
	}
}
func TestHarnessDoesNotConfuseTimeoutsOrTruncationWithDenial(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	h, err := newHarness(options{gantry: executable, cliOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(h.root) })
	h.env = environment(h.env, map[string]string{"GANTRY_POLICY_E2E_HELPER": "1"})
	args := func(mode string) []string { return []string{"-test.run=^TestHarnessHelperProcess$", "--", mode} }
	result, err := h.command(context.Background(), "", args("deny")...)
	if err != nil || result.code != 23 || !strings.Contains(result.output, "OPA-DENIED") {
		t.Fatalf("real exit lost: %+v %v", result, err)
	}
	if _, err := h.command(context.Background(), "", args("large")...); err == nil {
		t.Fatal("output truncation was not a harness failure")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := h.command(ctx, "", args("hang")...); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout was treated as guest denial: %v", err)
	}
	result, err = h.command(context.Background(), "", args("secret")...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.output, h.secrets[0]) {
		t.Fatal("assertions need the actual credential value")
	}
	log, err := os.ReadFile(filepath.Join(h.root, "commands.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), h.secrets[0]) || !strings.Contains(string(log), "[E2E-CREDENTIAL]") {
		t.Fatal("diagnostics leaked a canary")
	}
}

type discardCloser struct{ io.Writer }

func (discardCloser) Close() error { return nil }
func TestMCPProcessFailureDoesNotStrandCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &mcpSession{ctx: ctx, cancel: cancel, stdin: discardCloser{io.Discard}, done: make(chan struct{}), responses: make(chan rpcResponse), err: fmt.Errorf("process failed")}
	close(s.done)
	if _, err := s.call("tools/list", nil); err == nil {
		t.Fatal("process exit did not fail pending call")
	}
	done := make(chan struct{})
	go func() { s.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup hung after call observed process exit")
	}
}

func TestLoopbackFixtureIsHealthyAndTracksCalls(t *testing.T) {
	e := newEndpoint("fixture-ready")
	defer e.Close()
	if err := e.healthy(time.Second); err != nil {
		t.Fatal(err)
	}
	if e.connections.Load() == 0 {
		t.Fatal("positive control did not create a connection")
	}
	request := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "read"}}
	raw, _ := json.Marshal(request)
	response, err := e.Client().Post(e.URL+"/mcp", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var result rpcResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.ID != 1 || e.callCount("read") != 1 || !strings.Contains(string(result.Result), "OPA-MCP-CALL-OK") {
		t.Fatal("MCP fixture did not track invocation")
	}
}
