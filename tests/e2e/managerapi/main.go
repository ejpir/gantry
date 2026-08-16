// managerapi is a black-box lifecycle test for `gantry serve`.
// It deliberately launches the real manager and a real VM; it is not run by
// `go test ./...` because a local hypervisor and Gantry guest assets are needed.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/guestasset"
)

const (
	builtInImage = "builtin"
	secretValue  = "manager-e2e-secret-value"
)

type options struct {
	gantry     string
	image      string
	kernel     string
	rootfs     string
	artifacts  string
	imageStore string
	workDir    string
	name       string
	pull       bool
	keep       bool
	timeout    time.Duration
}

type apiClient struct {
	http *http.Client
}

type operation struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Sandbox string `json:"sandbox"`
	State   string `json:"state"`
	Error   string `json:"error"`
}

type sandbox struct {
	Name  string `json:"name"`
	State string `json:"state"`
	PID   int    `json:"pid"`
}

type event struct {
	ID          uint64 `json:"id"`
	Type        string `json:"type"`
	OperationID string `json:"operationId"`
	Sandbox     string `json:"sandbox"`
	State       string `json:"state"`
}

type eventSink struct {
	mu     sync.Mutex
	events []event
	wake   chan struct{}
}

func main() {
	var opts options
	flag.StringVar(&opts.gantry, "gantry", "", "existing Gantry binary (default: build ./cmd/gantry)")
	flag.StringVar(&opts.image, "image", builtInImage, "builtin, cached OCI image reference, or .erofs path")
	flag.StringVar(&opts.kernel, "kernel", "", "explicit guest kernel")
	flag.StringVar(&opts.rootfs, "rootfs", "", "explicit guest initramfs")
	flag.StringVar(&opts.artifacts, "artifacts", "", "GANTRY_ARTIFACTS override")
	flag.StringVar(&opts.imageStore, "image-store", "", "GANTRY_IMAGES override")
	flag.StringVar(&opts.workDir, "work-dir", "", "preserved test workspace (default: temporary)")
	flag.StringVar(&opts.name, "name", "manager-e2e", "sandbox name")
	flag.BoolVar(&opts.pull, "pull", true, "pull the image before starting the manager")
	flag.BoolVar(&opts.keep, "keep", false, "keep the workspace after success")
	flag.DurationVar(&opts.timeout, "timeout", 10*time.Minute, "overall timeout")
	flag.Parse()

	if err := run(opts); err != nil {
		fmt.Fprintln(os.Stderr, "manager API E2E:", err)
		os.Exit(1)
	}
}

func run(opts options) (runErr error) {
	repo, err := os.Getwd()
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(repo, "go.mod")); err != nil {
		return fmt.Errorf("run from the Gantry repository root: %w", err)
	}

	work := opts.workDir
	temporary := work == ""
	if temporary {
		parent := ""
		// Darwin's sockaddr_un.sun_path is only 104 bytes. os.TempDir on
		// macOS expands below /var/folders/... and leaves too little room for
		// the sandbox's nested vsock endpoints. /tmp is deliberately short,
		// private after MkdirTemp, and also avoids Linux's 108-byte limit.
		if runtime.GOOS != "windows" {
			if info, statErr := os.Stat("/tmp"); statErr == nil && info.IsDir() {
				parent = "/tmp"
			}
		}
		work, err = os.MkdirTemp(parent, "gme-")
	} else {
		err = os.MkdirAll(work, 0o700)
	}
	if err != nil {
		return fmt.Errorf("create workspace: %w", err)
	}
	work, err = filepath.Abs(work)
	if err != nil {
		return err
	}
	if err := checkSocketPathBudget(work, opts.name); err != nil {
		return err
	}
	logPath := filepath.Join(work, "manager.log")
	fmt.Println("workspace:", work)
	defer func() {
		if runErr != nil {
			fmt.Fprintln(os.Stderr, "manager log:", logPath)
			printLogTail(logPath, 80)
			return
		}
		if temporary && !opts.keep {
			_ = os.RemoveAll(work)
		} else {
			fmt.Println("kept workspace:", work)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	gantry := opts.gantry
	if gantry == "" {
		gantry = filepath.Join(work, executableName("gantry-e2e"))
		if err := step("build Gantry", func() error { return buildGantry(ctx, repo, gantry) }); err != nil {
			return err
		}
	} else if gantry, err = filepath.Abs(gantry); err != nil {
		return err
	}

	sandboxRoot := filepath.Join(work, "sandboxes")
	socketPath := filepath.Join(work, "manager.sock")
	env := environment(map[string]string{
		"GANTRY_HOME":           sandboxRoot,
		"GANTRY_MANAGER_SOCKET": socketPath,
		"MANAGER_E2E_SECRET":    secretValue,
	})
	if opts.artifacts != "" {
		env = environmentFrom(env, map[string]string{"GANTRY_ARTIFACTS": opts.artifacts})
	}
	if opts.imageStore != "" {
		env = environmentFrom(env, map[string]string{"GANTRY_IMAGES": opts.imageStore})
	}

	if opts.image == builtInImage {
		if err := step("cache built-in image", func() error {
			var err error
			opts.image, err = ensureBuiltInImage(work)
			return err
		}); err != nil {
			return err
		}
	} else if opts.pull && !isLocalImage(opts.image) {
		if err := step("cache image", func() error {
			return runCommand(ctx, repo, env, gantry, "image", "pull", opts.image)
		}); err != nil {
			return err
		}
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	manager := exec.CommandContext(ctx, gantry, "serve", "-socket", socketPath)
	manager.Dir = repo
	manager.Env = env
	manager.Stdout = logFile
	manager.Stderr = logFile
	if err := manager.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("start manager: %w", err)
	}
	managerExited := make(chan struct{})
	var managerErr error
	go func() {
		managerErr = manager.Wait()
		close(managerExited)
	}()
	defer func() {
		if manager.Process != nil {
			_ = manager.Process.Signal(os.Interrupt)
			select {
			case <-managerExited:
			case <-time.After(3 * time.Second):
				_ = manager.Process.Kill()
				<-managerExited
			}
		}
		_ = logFile.Close()
	}()

	client := newAPIClient(socketPath)
	if err := step("manager readiness", func() error {
		return waitForHealth(ctx, client, managerExited, func() error { return managerErr })
	}); err != nil {
		return err
	}

	eventCtx, stopEvents := context.WithCancel(ctx)
	defer stopEvents()
	sink := &eventSink{wake: make(chan struct{}, 1)}
	streamReady := make(chan error, 1)
	go readEvents(eventCtx, client, sink, streamReady)
	if err := <-streamReady; err != nil {
		return fmt.Errorf("open event stream: %w", err)
	}

	created := false
	defer func() {
		if created {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			_, _, _, _ = client.do(cleanupCtx, http.MethodDelete, "/v1/sandboxes/"+opts.name, nil, nil)
		}
	}()

	if err := step("health and OpenAPI", func() error { return testContract(ctx, client) }); err != nil {
		return err
	}
	if err := step("empty sandbox list", func() error { return expectSandboxCount(ctx, client, 0) }); err != nil {
		return err
	}
	if err := step("strict request validation", func() error { return testValidation(ctx, client) }); err != nil {
		return err
	}

	createBody, err := json.Marshal(map[string]any{
		"name": opts.name, "image": opts.image, "kernel": opts.kernel, "rootfs": opts.rootfs,
		"rw": false, "net": false, "oauthBridge": false, "processIsolation": "auto",
		"memoryMiB": 512, "cpus": 1, "secretNames": []string{"MANAGER_E2E_SECRET"},
	})
	if err != nil {
		return err
	}
	var createOp operation
	if err := step("create real sandbox", func() error {
		// A failed create can still leave partially published state. Make the
		// deferred DELETE active before sending the request so diagnostics and
		// retries do not inherit it when a caller supplies a persistent work dir.
		created = true
		status, body, _, err := client.do(ctx, http.MethodPost, "/v1/sandboxes", createBody, map[string]string{"Idempotency-Key": "create-1"})
		if err != nil {
			return err
		}
		if status != http.StatusCreated {
			return statusError(status, body, http.StatusCreated)
		}
		if err := json.Unmarshal(body, &createOp); err != nil {
			return err
		}
		if createOp.ID == "" || createOp.State != "succeeded" {
			return fmt.Errorf("unexpected create operation: %+v", createOp)
		}
		return sink.wait(ctx, createOp.ID, "succeeded")
	}); err != nil {
		return err
	}

	if err := step("operation lookup and idempotency", func() error {
		return testOperationAndReplay(ctx, client, createBody, createOp)
	}); err != nil {
		return err
	}
	if err := step("running sandbox state", func() error { return expectSandboxState(ctx, client, opts.name, "running") }); err != nil {
		return err
	}
	if err := step("captured exec semantics", func() error { return testExec(ctx, client, opts.name) }); err != nil {
		return err
	}
	if err := step("secret is not persisted", func() error {
		config, err := os.ReadFile(filepath.Join(sandboxRoot, opts.name, "sandbox.json"))
		if err != nil {
			return err
		}
		if !bytes.Contains(config, []byte("MANAGER_E2E_SECRET")) || bytes.Contains(config, []byte(secretValue)) {
			return errors.New("sandbox config must contain the secret name but never its value")
		}
		return nil
	}); err != nil {
		return err
	}

	if err := lifecycle(ctx, client, sink, http.MethodPost, "/v1/sandboxes/"+opts.name+"/stop", "stop-1"); err != nil {
		return fmt.Errorf("stop sandbox: %w", err)
	}
	if err := step("stopped sandbox rejects exec", func() error {
		if err := expectSandboxState(ctx, client, opts.name, "stopped"); err != nil {
			return err
		}
		status, body, _, err := client.do(ctx, http.MethodPost, "/v1/sandboxes/"+opts.name+"/exec", []byte(`{"argv":["true"]}`), nil)
		if err != nil {
			return err
		}
		return expectStatus(status, body, http.StatusConflict)
	}); err != nil {
		return err
	}
	if err := lifecycle(ctx, client, sink, http.MethodPost, "/v1/sandboxes/"+opts.name+"/start", "start-1"); err != nil {
		return fmt.Errorf("restart sandbox: %w", err)
	}
	if err := step("exec after restart", func() error {
		if err := expectSandboxState(ctx, client, opts.name, "running"); err != nil {
			return err
		}
		return expectExec(ctx, client, opts.name, []byte(`{"argv":["/bin/sh","-c","printf restarted"]}`), 0, "restarted")
	}); err != nil {
		return err
	}

	deletePath := "/v1/sandboxes/" + opts.name
	var deleteOp operation
	if err := step("delete and replay", func() error {
		status, body, _, err := client.do(ctx, http.MethodDelete, deletePath, nil, map[string]string{"Idempotency-Key": "delete-1"})
		if err != nil {
			return err
		}
		if err := expectStatus(status, body, http.StatusOK); err != nil {
			return err
		}
		if err := json.Unmarshal(body, &deleteOp); err != nil {
			return err
		}
		if err := sink.wait(ctx, deleteOp.ID, "succeeded"); err != nil {
			return err
		}
		status, replay, _, err := client.do(ctx, http.MethodDelete, deletePath, nil, map[string]string{"Idempotency-Key": "delete-1"})
		if err != nil {
			return err
		}
		var replayOp operation
		if err := json.Unmarshal(replay, &replayOp); err != nil {
			return err
		}
		if status != http.StatusOK || replayOp.ID != deleteOp.ID {
			return fmt.Errorf("delete replay status=%d id=%q, want 200 id=%q", status, replayOp.ID, deleteOp.ID)
		}
		return nil
	}); err != nil {
		return err
	}
	created = false
	if err := step("final sandbox state", func() error {
		status, body, _, err := client.do(ctx, http.MethodGet, deletePath, nil, nil)
		if err != nil {
			return err
		}
		if err := expectStatus(status, body, http.StatusNotFound); err != nil {
			return err
		}
		return expectSandboxCount(ctx, client, 0)
	}); err != nil {
		return err
	}

	fmt.Println("manager API E2E passed")
	return nil
}

func buildGantry(ctx context.Context, repo, output string) error {
	if err := runCommand(ctx, repo, os.Environ(), "go", "build", "-trimpath", "-o", output, "./cmd/gantry"); err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		return runCommand(ctx, repo, os.Environ(), "codesign", "--force", "--sign", "-", "--entitlements", filepath.Join(repo, "config", "entitlements.plist"), output)
	}
	return nil
}

func newAPIClient(socket string) *apiClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
		DisableCompression: true,
	}
	return &apiClient{http: &http.Client{Transport: transport}}
}

func (c *apiClient) do(ctx context.Context, method, path string, body []byte, headers map[string]string) (int, []byte, http.Header, error) {
	request, err := http.NewRequestWithContext(ctx, method, "http://gantry.local"+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 20<<20))
	return response.StatusCode, payload, response.Header, err
}

func waitForHealth(ctx context.Context, client *apiClient, managerExited <-chan struct{}, managerError func() error) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, _, _, err := client.do(ctx, http.MethodGet, "/v1/health", nil, nil)
		if err == nil && status == http.StatusOK {
			return nil
		}
		select {
		case <-managerExited:
			return fmt.Errorf("manager exited before readiness: %w", managerError())
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func testContract(ctx context.Context, client *apiClient) error {
	status, body, headers, err := client.do(ctx, http.MethodGet, "/v1/health", nil, nil)
	if err != nil {
		return err
	}
	if err := expectStatus(status, body, http.StatusOK); err != nil {
		return err
	}
	if !bytes.Contains(body, []byte(`"ok":true`)) || headers.Get("X-Content-Type-Options") != "nosniff" {
		return fmt.Errorf("unexpected health response: headers=%v body=%s", headers, body)
	}
	status, body, _, err = client.do(ctx, http.MethodGet, "/v1/openapi.yaml", nil, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK || !bytes.Contains(body, []byte("/v1/sandboxes/{name}/exec:")) {
		return fmt.Errorf("OpenAPI response status=%d does not contain exec contract", status)
	}
	return nil
}

func testValidation(ctx context.Context, client *apiClient) error {
	status, body, _, err := client.do(ctx, http.MethodPost, "/v1/sandboxes", []byte(`{"name":"invalid"}`), nil)
	if err != nil {
		return err
	}
	if err := expectStatus(status, body, http.StatusBadRequest); err != nil {
		return err
	}
	status, body, _, err = client.do(ctx, http.MethodPost, "/v1/sandboxes/missing/exec", []byte(`{"argv":["true"],"unknown":true}`), nil)
	if err != nil {
		return err
	}
	return expectStatus(status, body, http.StatusBadRequest)
}

func testOperationAndReplay(ctx context.Context, client *apiClient, createBody []byte, want operation) error {
	status, body, _, err := client.do(ctx, http.MethodGet, "/v1/operations/"+want.ID, nil, nil)
	if err != nil {
		return err
	}
	var got operation
	if status != http.StatusOK || json.Unmarshal(body, &got) != nil || got.ID != want.ID || got.State != "succeeded" {
		return fmt.Errorf("operation lookup status=%d body=%s", status, body)
	}
	status, body, _, err = client.do(ctx, http.MethodPost, "/v1/sandboxes", createBody, map[string]string{"Idempotency-Key": "create-1"})
	if err != nil {
		return err
	}
	if status != http.StatusOK || json.Unmarshal(body, &got) != nil || got.ID != want.ID {
		return fmt.Errorf("create replay status=%d body=%s", status, body)
	}
	changed := append([]byte(nil), createBody...)
	changed = bytes.Replace(changed, []byte(`"cpus":1`), []byte(`"cpus":2`), 1)
	status, body, _, err = client.do(ctx, http.MethodPost, "/v1/sandboxes", changed, map[string]string{"Idempotency-Key": "create-1"})
	if err != nil {
		return err
	}
	return expectStatus(status, body, http.StatusConflict)
}

func testExec(ctx context.Context, client *apiClient, name string) error {
	payload, _ := json.Marshal(map[string]any{
		"argv": []string{"/bin/sh", "-c", `printf 'cwd=%s stdin=' "$PWD"; cat; printf ' secret=%s' "$MANAGER_E2E_SECRET"; exit 7`},
		"cwd":  "/tmp", "stdin": "hello", "timeoutSeconds": 10,
	})
	if err := expectExec(ctx, client, name, payload, 7, "cwd=/tmp stdin=hello secret="+secretValue); err != nil {
		return err
	}
	status, body, _, err := client.do(ctx, http.MethodPost, "/v1/sandboxes/"+name+"/exec", []byte(`{"argv":["/bin/sh","-c","yes x | head -c 4096"],"maxOutputBytes":128}`), nil)
	if err != nil {
		return err
	}
	if err := expectStatus(status, body, http.StatusRequestEntityTooLarge); err != nil {
		return fmt.Errorf("output limit: %w", err)
	}
	status, body, _, err = client.do(ctx, http.MethodPost, "/v1/sandboxes/"+name+"/exec", []byte(`{"argv":["sleep","3"],"timeoutSeconds":1}`), nil)
	if err != nil {
		return err
	}
	if err := expectStatus(status, body, http.StatusRequestTimeout); err != nil {
		return fmt.Errorf("timeout: %w", err)
	}
	return nil
}

func expectExec(ctx context.Context, client *apiClient, name string, payload []byte, exitCode int, contains string) error {
	status, body, _, err := client.do(ctx, http.MethodPost, "/v1/sandboxes/"+name+"/exec", payload, nil)
	if err != nil {
		return err
	}
	var result struct {
		ExitCode int    `json:"exitCode"`
		Output   string `json:"output"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &result) != nil {
		return fmt.Errorf("exec status=%d body=%s", status, body)
	}
	if result.ExitCode != exitCode || !strings.Contains(result.Output, contains) {
		return fmt.Errorf("exec result exit=%d output=%q, want exit=%d containing %q", result.ExitCode, result.Output, exitCode, contains)
	}
	return nil
}

func lifecycle(ctx context.Context, client *apiClient, sink *eventSink, method, path, key string) error {
	label := strings.TrimPrefix(path, "/v1/sandboxes/")
	return step(label, func() error {
		status, body, _, err := client.do(ctx, method, path, nil, map[string]string{"Idempotency-Key": key})
		if err != nil {
			return err
		}
		if err := expectStatus(status, body, http.StatusOK); err != nil {
			return err
		}
		var op operation
		if err := json.Unmarshal(body, &op); err != nil {
			return err
		}
		if op.State != "succeeded" {
			return fmt.Errorf("operation did not succeed: %+v", op)
		}
		return sink.wait(ctx, op.ID, "succeeded")
	})
}

func expectSandboxState(ctx context.Context, client *apiClient, name, state string) error {
	status, body, _, err := client.do(ctx, http.MethodGet, "/v1/sandboxes/"+name, nil, nil)
	if err != nil {
		return err
	}
	var got sandbox
	if status != http.StatusOK || json.Unmarshal(body, &got) != nil || got.Name != name || got.State != state {
		return fmt.Errorf("sandbox status=%d body=%s, want %s", status, body, state)
	}
	if state == "running" && got.PID <= 0 {
		return fmt.Errorf("running sandbox has invalid pid %d", got.PID)
	}
	return nil
}

func expectSandboxCount(ctx context.Context, client *apiClient, count int) error {
	status, body, _, err := client.do(ctx, http.MethodGet, "/v1/sandboxes", nil, nil)
	if err != nil {
		return err
	}
	var result struct {
		Sandboxes []sandbox `json:"sandboxes"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &result) != nil || len(result.Sandboxes) != count {
		return fmt.Errorf("sandbox list status=%d body=%s, want %d entries", status, body, count)
	}
	return nil
}

func readEvents(ctx context.Context, client *apiClient, sink *eventSink, ready chan<- error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://gantry.local/v1/events", nil)
	if err != nil {
		ready <- err
		return
	}
	response, err := client.http.Do(request)
	if err != nil {
		ready <- err
		return
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		ready <- fmt.Errorf("status %d", response.StatusCode)
		return
	}
	ready <- nil
	reader := bufio.NewReader(response.Body)
	for {
		event, err := readEvent(reader)
		if err != nil {
			return
		}
		sink.add(event)
	}
}

func readEvent(reader *bufio.Reader) (event, error) {
	var payload []byte
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return event{}, err
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if line == "" {
			if len(payload) == 0 {
				continue
			}
			var value event
			if err := json.Unmarshal(payload, &value); err != nil {
				return event{}, err
			}
			return value, nil
		}
		if strings.HasPrefix(line, "data:") {
			part := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if len(payload) != 0 {
				payload = append(payload, '\n')
			}
			payload = append(payload, part...)
		}
	}
}

func (s *eventSink) add(value event) {
	s.mu.Lock()
	s.events = append(s.events, value)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *eventSink) wait(ctx context.Context, operationID, state string) error {
	for {
		s.mu.Lock()
		for _, value := range s.events {
			if value.OperationID == operationID && value.State == state {
				s.mu.Unlock()
				return nil
			}
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for event operation=%s state=%s: %w", operationID, state, ctx.Err())
		case <-s.wake:
		}
	}
}

func step(name string, fn func() error) error {
	fmt.Printf("=== RUN   %s\n", name)
	started := time.Now()
	if err := fn(); err != nil {
		fmt.Printf("--- FAIL: %s (%.2fs)\n", name, time.Since(started).Seconds())
		return fmt.Errorf("%s: %w", name, err)
	}
	fmt.Printf("--- PASS: %s (%.2fs)\n", name, time.Since(started).Seconds())
	return nil
}

func expectStatus(got int, body []byte, want int) error {
	if got != want {
		return statusError(got, body, want)
	}
	return nil
}

func statusError(got int, body []byte, want int) error {
	return fmt.Errorf("HTTP %d, want %d: %s", got, want, strings.TrimSpace(string(body)))
}

func executableName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func checkSocketPathBudget(work, sandboxName string) error {
	limit := 107 // Linux and Windows AF_UNIX: 108 bytes including trailing NUL.
	if runtime.GOOS == "darwin" {
		limit = 103 // Darwin: 104 bytes including trailing NUL.
	}
	longest := filepath.Join(work, "sandboxes", sandboxName, "listen-1026.sock")
	if len([]byte(longest)) > limit {
		return fmt.Errorf("workspace path is too long for %s Unix sockets (%d > %d bytes): %s; use -work-dir /tmp/gme",
			runtime.GOOS, len([]byte(longest)), limit, longest)
	}
	return nil
}

func isLocalImage(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func ensureBuiltInImage(work string) (string, error) {
	name := "gantry-default-image-arm64.erofs"
	if runtime.GOARCH == "amd64" {
		name = "gantry-default-image-x86_64.erofs"
	}
	root, err := os.UserCacheDir()
	if err != nil || root == "" {
		root = filepath.Join(work, "cache")
	}
	destination := filepath.Join(root, "gantry", "e2e-assets", name)
	return guestasset.EnsureImage(destination, func(format string, args ...any) {
		fmt.Printf(format+"\n", args...)
	})
}

func runCommand(ctx context.Context, dir string, env []string, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	command.Env = env
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func environment(overrides map[string]string) []string {
	return environmentFrom(os.Environ(), overrides)
}

func environmentFrom(base []string, overrides map[string]string) []string {
	values := make(map[string]string, len(base)+len(overrides))
	for _, entry := range base {
		if index := strings.IndexByte(entry, '='); index >= 0 {
			values[entry[:index]] = entry[index+1:]
		}
	}
	for key, value := range overrides {
		values[key] = value
	}
	result := make([]string, 0, len(values))
	for key, value := range values {
		result = append(result, key+"="+value)
	}
	return result
}

func printLogTail(path string, lines int) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	parts := strings.Split(string(data), "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	fmt.Fprintln(os.Stderr, "--- manager.log tail ---")
	fmt.Fprintln(os.Stderr, strings.Join(parts, "\n"))
}
