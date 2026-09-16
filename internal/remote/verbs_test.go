package remote

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/ejpir/gantry/api/managerapi"
)

// verbHarness wires a stub manager to runVerb with captured output.
func verbHarness(t *testing.T, handler http.Handler) (*Client, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	_, profile := stubManager(t, handler)
	client, err := Dial(profile, testToken)
	if err != nil {
		t.Fatal(err)
	}
	return client, &bytes.Buffer{}, &bytes.Buffer{}
}

// stdinPipe returns a non-terminal *os.File carrying the given input.
func stdinPipe(t *testing.T, input string) *os.File {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString(input); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	return reader
}

func TestRemoteLsFormatsTable(t *testing.T) {
	client, output, errorOutput := verbHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"sandboxes": []managerapi.Sandbox{
			{Name: "dev", State: "running", PID: 42, Image: "alpine"},
			{Name: "old", State: "stopped", ImageRef: "debian:bookworm"},
		}})
	}))
	if status := runVerb(t.Context(), output, errorOutput, stdinPipe(t, ""), "ls", "stub", client, nil); status != 0 {
		t.Fatalf("ls = %d (%s)", status, errorOutput)
	}
	got := output.String()
	for _, want := range []string{"NAME", "dev", "running", "42", "alpine", "old", "stopped", "debian:bookworm"} {
		if !strings.Contains(got, want) {
			t.Errorf("ls output lacks %q:\n%s", want, got)
		}
	}
}

func TestRemoteLsEmpty(t *testing.T) {
	client, output, errorOutput := verbHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"sandboxes": []managerapi.Sandbox{}})
	}))
	if status := runVerb(t.Context(), output, errorOutput, stdinPipe(t, ""), "ls", "stub", client, nil); status != 0 {
		t.Fatalf("ls = %d (%s)", status, errorOutput)
	}
	if !strings.Contains(output.String(), `no sandboxes on remote "stub"`) {
		t.Errorf("empty ls = %q", output.String())
	}
}

func TestRemoteStartSendsRequest(t *testing.T) {
	var created managerapi.CreateSandboxRequest
	client, output, errorOutput := verbHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "op", Kind: "create", State: "succeeded"})
	}))
	status := runVerb(t.Context(), output, errorOutput, stdinPipe(t, ""), "start", "stub", client,
		[]string{"dev", "-image", "alpine:latest", "-mem", "1024", "-cpus", "2", "-rw", "-net=false",
			"-share", "code=/srv/code,ro", "-p", "127.0.0.1:8080:80", "-secret", "GITHUB_TOKEN"})
	if status != 0 {
		t.Fatalf("start = %d (%s)", status, errorOutput)
	}
	if created.Name != "dev" || created.Image != "alpine:latest" || created.MemoryMiB != 1024 || created.CPUs != 2 {
		t.Fatalf("create body = %+v", created)
	}
	if created.RW == nil || !*created.RW {
		t.Fatalf("explicit -rw lost: %+v", created)
	}
	if created.Net == nil || *created.Net {
		t.Fatalf("explicit -net=false lost: %+v", created)
	}
	if created.OAuthBridge != nil {
		t.Fatalf("unset -oauth-bridge must be omitted (server default), got %v", *created.OAuthBridge)
	}
	if len(created.Shares) != 1 || created.Shares[0] != "code=/srv/code,ro" ||
		len(created.Publish) != 1 || created.Publish[0] != "127.0.0.1:8080:80" ||
		len(created.SecretNames) != 1 || created.SecretNames[0] != "GITHUB_TOKEN" {
		t.Fatalf("create lists = %+v", created)
	}
	if !strings.Contains(output.String(), `sandbox "dev" is up on "stub"`) {
		t.Errorf("start output = %q", output.String())
	}
}

func TestRemoteStartRejectsLocalOnlyAndBadSecrets(t *testing.T) {
	client, output, errorOutput := verbHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached the server")
	}))
	if status := runVerb(t.Context(), output, errorOutput, stdinPipe(t, ""), "start", "stub", client,
		[]string{"dev", "-image", "alpine", "-oauth-custody"}); status != 2 ||
		!strings.Contains(errorOutput.String(), "-oauth-custody is not supported with -remote") {
		t.Fatalf("start -oauth-custody = %d (%s)", status, errorOutput)
	}
	errorOutput.Reset()
	if status := runVerb(t.Context(), output, errorOutput, stdinPipe(t, ""), "start", "stub", client,
		[]string{"dev", "-image", "alpine", "-secret", "NAME=@/home/user/file"}); status != 2 ||
		!strings.Contains(errorOutput.String(), "plain NAME") {
		t.Fatalf("start file secret = %d (%s)", status, errorOutput)
	}
	errorOutput.Reset()
	if status := runVerb(t.Context(), output, errorOutput, stdinPipe(t, ""), "start", "stub", client,
		[]string{"-image", "alpine"}); status != 2 {
		t.Fatalf("start without name = %d", status)
	}
}

func TestRemoteExecRunsAndPropagates(t *testing.T) {
	var request managerapi.ExecRequest
	client, output, errorOutput := verbHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(managerapi.ExecResult{ExitCode: 7, Output: "hello\n", Truncated: true})
	}))
	status := runVerb(t.Context(), output, errorOutput, stdinPipe(t, "stdin-bytes"), "exec", "stub", client,
		[]string{"dev", "-timeout", "60", "--", "sh", "-c", "exit 7"})
	if status != 7 {
		t.Fatalf("exec = %d, want the guest exit code", status)
	}
	if len(request.Argv) != 3 || request.Argv[0] != "sh" || request.TimeoutSeconds != 60 ||
		request.Stdin != "stdin-bytes" {
		t.Fatalf("exec request = %+v", request)
	}
	if output.String() != "hello\n" {
		t.Errorf("exec output = %q", output.String())
	}
	if !strings.Contains(errorOutput.String(), "truncated") {
		t.Errorf("truncation warning missing: %q", errorOutput.String())
	}
}

func TestRemoteExecRejectsInteractiveAndOneShot(t *testing.T) {
	client, output, errorOutput := verbHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached the server")
	}))
	if status := runVerb(t.Context(), output, errorOutput, stdinPipe(t, ""), "exec", "stub", client,
		[]string{"dev"}); status != 2 || !strings.Contains(errorOutput.String(), "interactive sessions are not available") {
		t.Fatalf("interactive exec = %d (%s)", status, errorOutput)
	}
	errorOutput.Reset()
	if status := runVerb(t.Context(), output, errorOutput, stdinPipe(t, ""), "exec", "stub", client,
		[]string{"-image", "alpine", "--", "sh"}); status != 2 || !strings.Contains(errorOutput.String(), "one-shot exec") {
		t.Fatalf("one-shot exec = %d (%s)", status, errorOutput)
	}
}

func TestRemoteLifecycleVerbs(t *testing.T) {
	calls := 0
	client, output, errorOutput := verbHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "op", Kind: "x", State: "succeeded"})
	}))
	for verb, want := range map[string]string{
		"stop":   `sandbox "dev" stopped on "stub"`,
		"delete": `sandbox "dev" deleted on "stub"`,
		"resume": `sandbox "dev" is up on "stub"`,
	} {
		output.Reset()
		if status := runVerb(t.Context(), output, errorOutput, stdinPipe(t, ""), verb, "stub", client, []string{"dev"}); status != 0 {
			t.Fatalf("%s = %d (%s)", verb, status, errorOutput)
		}
		if !strings.Contains(output.String(), want) {
			t.Errorf("%s output = %q, want %q", verb, output.String(), want)
		}
	}
	if calls != 3 {
		t.Fatalf("%d server calls, want 3", calls)
	}
	if status := runVerb(t.Context(), output, errorOutput, stdinPipe(t, ""), "stop", "stub", client, nil); status != 2 {
		t.Fatalf("stop without name = %d", status)
	}
}

func TestRunVerbUnknownRemoteFailsLoudly(t *testing.T) {
	testHome(t)
	addTestProfile(t, "cloud")
	// RunVerb resolves through the store; an unknown target must be an
	// error, never a local action.
	if status := RunVerb("ls", "nope", nil); status != 1 {
		t.Fatalf("RunVerb unknown remote = %d", status)
	}
}
