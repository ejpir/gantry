// managerapi is a black-box lifecycle test for `gantry serve`.
// It deliberately launches the real manager and a real VM; it is not run by
// `go test ./...` because a local hypervisor and Gantry guest assets are needed.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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

	"github.com/ejpir/gantry/api/managerapi"
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
	tls        bool
	apiOnly    bool
	timeout    time.Duration
}

type apiClient struct {
	http    *http.Client
	baseURL string
	token   string // set only after the unauthenticated transport checks
}

// tlsHarness holds the state for the manager's network transport checks.
type tlsHarness struct {
	token     string
	tokenPath string
	address   string
}

type operation = managerapi.Operation
type sandbox = managerapi.Sandbox
type event = managerapi.Event

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
	flag.BoolVar(&opts.tls, "tls", true, "also exercise the TLS + bearer-token manager transport")
	flag.BoolVar(&opts.apiOnly, "api-only", false, "run real-manager auth/dispatch/configure/run checks without assets or VM boot (requires TLS)")
	flag.DurationVar(&opts.timeout, "timeout", 10*time.Minute, "overall timeout")
	flag.Parse()

	if err := run(opts); err != nil {
		fmt.Fprintln(os.Stderr, "manager API E2E:", err)
		os.Exit(1)
	}
}

func run(opts options) (runErr error) {
	if opts.apiOnly && !opts.tls {
		return fmt.Errorf("-api-only requires -tls=true; remote tests must not be silently skipped")
	}
	if opts.tls && !opts.apiOnly {
		if err := requireOpenSSH(); err != nil {
			return err
		}
	}
	repo, err := os.Getwd()
	if err != nil {
		return err
	}
	if opts.gantry == "" {
		if _, err := os.Stat(filepath.Join(repo, "go.mod")); err != nil {
			return fmt.Errorf("run from the Gantry repository root when building Gantry: %w", err)
		}
	} else {
		gantry, err := filepath.Abs(opts.gantry)
		if err != nil {
			return err
		}
		opts.gantry = gantry
		// A prebuilt field driver is standalone. Use the supplied binary's
		// directory for child commands rather than requiring source on hosts.
		repo = filepath.Dir(gantry)
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
		"GANTRY_REMOTE":         "",
	})
	if opts.artifacts != "" {
		env = environmentFrom(env, map[string]string{"GANTRY_ARTIFACTS": opts.artifacts})
	}
	if opts.imageStore != "" {
		env = environmentFrom(env, map[string]string{"GANTRY_IMAGES": opts.imageStore})
	}

	var policyFeed *policyFeedHarness
	if !opts.apiOnly {
		if err := step("prepare mTLS policy feed", func() error {
			var err error
			policyFeed, err = setupPolicyFeed(ctx, repo, env, gantry, work)
			return err
		}); err != nil {
			return err
		}
		defer policyFeed.Close()
	}

	if !opts.apiOnly && opts.image == builtInImage {
		if err := step("cache built-in image", func() error {
			var err error
			opts.image, err = ensureBuiltInImage(work)
			return err
		}); err != nil {
			return err
		}
	} else if !opts.apiOnly && opts.pull && !isLocalImage(opts.image) {
		if err := step("cache image", func() error {
			return runCommand(ctx, repo, env, gantry, "image", "pull", opts.image)
		}); err != nil {
			return err
		}
	}

	// The default coverage uses the historical -socket spelling; enabling the
	// network transport switches to the explicit -listen form so both flag
	// styles stay exercised.
	remote := tlsHarness{}
	serveArgs := []string{"serve", "-socket", socketPath}
	if opts.tls {
		if err := step("mint manager token", func() error {
			var err error
			remote, err = setupTLSHarness(ctx, repo, env, gantry, work)
			return err
		}); err != nil {
			return err
		}
		serveArgs = []string{"serve",
			"-listen", "unix://" + socketPath,
			"-listen", "tls://" + remote.address,
			"--self-signed", "--token-file", remote.tokenPath}
	}
	if policyFeed != nil {
		serveArgs = append(serveArgs, "--policy-feed", policyFeed.configPath)
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	manager := exec.CommandContext(ctx, gantry, serveArgs...)
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

	// The network transport checks run entirely before any VM work: the TLS
	// listener, token authentication, and audit behavior are manager-only.
	var remoteClient *apiClient
	var m2 *m2Client
	if remote.token != "" {
		if err := step("tls transport and pinning", func() error {
			var err error
			remoteClient, err = newPinnedTLSClient(remote.address, filepath.Join(work, "serve", "ca.crt"), logPath)
			return err
		}); err != nil {
			return err
		}
		if err := step("tls bearer authentication", func() error {
			return testTLSAuthn(ctx, remoteClient, remote.token)
		}); err != nil {
			return err
		}
		if err := step("tls plaintext refusal", func() error {
			return testTLSPlaintextRefused(remote.address)
		}); err != nil {
			return err
		}
		if err := step("tls token rotation", func() error {
			newToken, err := testTLSRotation(ctx, repo, env, gantry, remoteClient, remote, logPath)
			if err != nil {
				return err
			}
			remote.token = newToken // subsequent checks run as the rotated token
			return nil
		}); err != nil {
			return err
		}
		if err := step("remote profile and dispatch", func() error {
			return testRemoteDispatch(ctx, repo, env, gantry, remote, logPath)
		}); err != nil {
			return err
		}
		remoteClient.token = remote.token
		if err := step("M2 isolated remote client and wrong-pin refusal", func() error {
			var err error
			m2, err = newM2Client(ctx, work, gantry, sandboxRoot, logPath, env, remote, remoteClient)
			return err
		}); err != nil {
			return err
		}
		if err := step("M2 configure, raw run, idempotency and no local fallback", func() error {
			return m2.stoppedAndRunChecks(ctx)
		}); err != nil {
			return err
		}
		// The full lifecycle and SSE battery now exercises authenticated TLS,
		// not just a Unix-only lifecycle with an independent TLS health probe.
		client = remoteClient
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
			cleanupSandbox(ctx, client, sandboxRoot, opts.name, runErr != nil)
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

	if opts.apiOnly {
		fmt.Println("manager API E2E passed (API-only; real manager/helpers, no VM boot)")
		return nil
	}

	createBody, err := json.Marshal(map[string]any{
		"name": opts.name, "image": opts.image, "kernel": opts.kernel, "rootfs": opts.rootfs,
		"rw": false, "net": true, "oauthBridge": false, "processIsolation": "auto",
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
	if remoteClient != nil {
		if err := step("tls mutation audit", func() error {
			return testTLSAudit(ctx, remoteClient, remote.token, opts.name, logPath)
		}); err != nil {
			return err
		}
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

	// Complete the real low-level VM deadline check before activating the
	// organization-wide feed. Raw runs are deliberately refused after policy
	// publication because they have no named sandbox enforcement points.
	if m2 != nil {
		if err := step("real remote CLI lifecycle, SSH/SFTP, live configure and raw VM deadline", func() error { return m2.lifecycleChecks(ctx, opts) }); err != nil {
			return err
		}
		if _, _, err := m2.cli(ctx, 0, "remote", "rm", "m2"); err != nil {
			return err
		}
		m2 = nil
	}

	if err := step("organization-wide mTLS policy feed live update", func() error {
		return testPolicyFeedRollout(ctx, client, policyFeed, opts.name, createBody)
	}); err != nil {
		return err
	}
	if err := step("organization policy refuses unmanaged raw VM", func() error {
		kernel, rootfs := opts.kernel, opts.rootfs
		if kernel == "" {
			kernel = guestasset.DefaultKernel()
		}
		if rootfs == "" {
			rootfs = guestasset.DefaultRootfs()
		}
		request, err := json.Marshal(map[string]any{"kernel": kernel, "rootfs": rootfs})
		if err != nil {
			return err
		}
		status, body, _, err := client.do(ctx, http.MethodPost, "/v1/run", request, map[string]string{"Idempotency-Key": "raw-policy-refused-1"})
		if err != nil {
			return err
		}
		if status != http.StatusConflict || !bytes.Contains(body, []byte("disabled while an organization-wide policy feed is active")) {
			return fmt.Errorf("organization-managed raw run status=%d body=%s", status, body)
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
	return &apiClient{http: &http.Client{Transport: transport}, baseURL: "http://gantry.local"}
}

func (c *apiClient) do(ctx context.Context, method, path string, body []byte, headers map[string]string) (int, []byte, http.Header, error) {
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
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
	var result managerapi.ExecResult
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
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+"/v1/events", nil)
	if err != nil {
		ready <- err
		return
	}
	if client.token != "" {
		request.Header.Set("Authorization", "Bearer "+client.token)
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

// setupTLSHarness mints a manager token, writes the token file, and picks a
// loopback port for the tls:// listener.
func setupTLSHarness(ctx context.Context, repo string, env []string, gantry, work string) (tlsHarness, error) {
	token, err := runCommandOutput(ctx, repo, env, gantry, "serve", "--mint-token")
	if err != nil {
		return tlsHarness{}, err
	}
	if len(token) < 32 {
		return tlsHarness{}, fmt.Errorf("minted token is suspiciously short (%d chars)", len(token))
	}
	tokenPath := filepath.Join(work, "manager-tokens")
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		return tlsHarness{}, err
	}
	port, err := freeLoopbackPort()
	if err != nil {
		return tlsHarness{}, err
	}
	return tlsHarness{token: token, tokenPath: tokenPath, address: fmt.Sprintf("127.0.0.1:%d", port)}, nil
}

func runCommandOutput(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	command.Env = env
	var stdout bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func freeLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	return port, listener.Close()
}

// newPinnedTLSClient builds the remote-transport client the way the design
// intends real clients to work: standard chain verification against the CA
// the manager wrote, plus pinning of the exact leaf fingerprint the manager
// printed at startup. No verification is skipped anywhere.
func newPinnedTLSClient(address, caPath, logPath string) (*apiClient, error) {
	fingerprint, err := tlsFingerprintFromLog(logPath)
	if err != nil {
		return nil, err
	}
	expected, err := hex.DecodeString(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("manager log fingerprint is not hex: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read manager CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("manager CA %s has no certificates", caPath)
	}
	tlsConfig := &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("manager presented no certificates")
			}
			sum := sha256.Sum256(rawCerts[0])
			if !bytes.Equal(sum[:], expected) {
				return fmt.Errorf("tls fingerprint mismatch: got sha256:%x, want sha256:%s", sum, fingerprint)
			}
			return nil
		},
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DisableCompression: true}
	return &apiClient{http: &http.Client{Transport: transport}, baseURL: "https://" + address}, nil
}

// tlsFingerprintFromLog extracts the fingerprint the manager printed for its
// self-signed TLS material.
func tlsFingerprintFromLog(logPath string) (string, error) {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return "", err
	}
	const marker = "tls fingerprint sha256:"
	index := bytes.Index(data, []byte(marker))
	if index < 0 {
		return "", fmt.Errorf("manager log has no tls fingerprint line")
	}
	rest := data[index+len(marker):]
	if len(rest) < 64 {
		return "", fmt.Errorf("truncated tls fingerprint in manager log")
	}
	return string(rest[:64]), nil
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func e2eTokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:4])
}

// testTLSAuthn checks the authentication matrix: every path requires a
// token, failures are indistinguishable, and a valid token is served.
func testTLSAuthn(ctx context.Context, client *apiClient, token string) error {
	status, missingBody, _, err := client.do(ctx, http.MethodGet, "/v1/health", nil, nil)
	if err != nil {
		return err
	}
	if err := expectStatus(status, missingBody, http.StatusForbidden); err != nil {
		return fmt.Errorf("health without token: %w", err)
	}
	for _, path := range []string{"/v1/openapi.yaml", "/v1/sandboxes", "/v1/events", "/v1/ssh/hostkey"} {
		status, body, _, err := client.do(ctx, http.MethodGet, path, nil, nil)
		if err != nil {
			return err
		}
		if err := expectStatus(status, body, http.StatusForbidden); err != nil {
			return fmt.Errorf("%s without token: %w", path, err)
		}
	}
	status, wrongBody, _, err := client.do(ctx, http.MethodGet, "/v1/health", nil, bearer("wrong-wrong-wrong-wrong"))
	if err != nil {
		return err
	}
	if err := expectStatus(status, wrongBody, http.StatusForbidden); err != nil {
		return fmt.Errorf("health with wrong token: %w", err)
	}
	if !bytes.Equal(missingBody, wrongBody) {
		return fmt.Errorf("missing-token body %q differs from wrong-token body %q", missingBody, wrongBody)
	}
	for _, authorization := range []string{"", "Bearer wrong-wrong-wrong-wrong"} {
		status, body, _, err := client.do(ctx, http.MethodPost, "/v1/sandboxes/m2-lifecycle/ssh", nil,
			map[string]string{"Authorization": authorization, "Connection": "Upgrade", "Upgrade": "gantry-ssh"})
		if err != nil {
			return err
		}
		if status != http.StatusForbidden || !bytes.Equal(body, missingBody) {
			return fmt.Errorf("unauthenticated SSH upgrade was not uniformly refused: %d %s", status, body)
		}
	}
	status, body, _, err := client.do(ctx, http.MethodGet, "/v1/health", nil, bearer(token))
	if err != nil {
		return err
	}
	if err := expectStatus(status, body, http.StatusOK); err != nil {
		return fmt.Errorf("health with token: %w", err)
	}
	if !bytes.Contains(body, []byte(`"ok":true`)) {
		return fmt.Errorf("unexpected health body over TLS: %s", body)
	}
	return nil
}

// testTLSPlaintextRefused verifies a plaintext HTTP request against the TLS
// port is never served as HTTP.
func testTLSPlaintextRefused(address string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + address + "/v1/health")
	if err != nil {
		return nil // handshake failure: the server dropped the plaintext request
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusBadRequest {
		return nil // Go's server-level "client sent HTTP to an HTTPS server"
	}
	return fmt.Errorf("plaintext HTTP on TLS port returned HTTP %d", response.StatusCode)
}

// testTLSAudit runs one mutating request over the network transport and
// verifies the audit record: remote address, token fingerprint, and status
// are logged — and the token value never is.
func testTLSAudit(ctx context.Context, client *apiClient, token, name, logPath string) error {
	status, body, _, err := client.do(ctx, http.MethodPost, "/v1/sandboxes/"+name+"/exec",
		[]byte(`{"argv":["/bin/sh","-c","printf tls-ok"],"timeoutSeconds":10}`), bearer(token))
	if err != nil {
		return err
	}
	if err := expectStatus(status, body, http.StatusOK); err != nil {
		return fmt.Errorf("exec over TLS: %w", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		return err
	}
	if bytes.Contains(data, []byte(token)) {
		return errors.New("manager log contains the raw bearer token")
	}
	for _, want := range []string{
		"tokenfp=" + e2eTokenFingerprint(token),
		"method=POST path=/v1/sandboxes/" + name + "/exec status=200",
		"remote=127.0.0.1:",
	} {
		if !bytes.Contains(data, []byte(want)) {
			return fmt.Errorf("manager log lacks %q", want)
		}
	}
	return nil
}

// testTLSRotation rewrites the token file, verifies the running manager
// picks the new token up and rejects the old one without a restart, and
// returns the now-current token for subsequent checks.
func testTLSRotation(ctx context.Context, repo string, env []string, gantry string, client *apiClient, remote tlsHarness, logPath string) (string, error) {
	newToken, err := runCommandOutput(ctx, repo, env, gantry, "serve", "--mint-token")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(remote.tokenPath, []byte(newToken+"\n"), 0o600); err != nil {
		return "", err
	}
	// Size and mtime granularity both hide same-length rewrites; force mtime.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(remote.tokenPath, future, future); err != nil {
		return "", err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		oldStatus, _, _, oldErr := client.do(ctx, http.MethodGet, "/v1/health", nil, bearer(remote.token))
		newStatus, body, _, newErr := client.do(ctx, http.MethodGet, "/v1/health", nil, bearer(newToken))
		if oldErr == nil && newErr == nil && oldStatus == http.StatusForbidden && newStatus == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("token rotation not picked up: old=%d new=%d (new body %s)", oldStatus, newStatus, body)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		return "", err
	}
	if bytes.Contains(data, []byte(newToken)) {
		return "", errors.New("manager log contains the rotated bearer token")
	}
	return newToken, nil
}

// testRemoteDispatch drives the real remote client (milestone 2) against
// the live manager: profile add with CA + fingerprint, remote test, verb
// dispatch via flag and environment, and the local-only refusal.
func testRemoteDispatch(ctx context.Context, repo string, env []string, gantry string, remote tlsHarness, logPath string) error {
	fingerprint, err := tlsFingerprintFromLog(logPath)
	if err != nil {
		return err
	}
	caPath := filepath.Join(filepath.Dir(remote.tokenPath), "serve", "ca.crt")
	// The token file holds the rotated token by now; add probes health.
	if _, err := runCommandOutput(ctx, repo, env, gantry, "remote", "add", "stub", "https://"+remote.address,
		"--token-file", remote.tokenPath, "--ca", caPath, "--fingerprint", "sha256:"+fingerprint); err != nil {
		return fmt.Errorf("remote add: %w", err)
	}
	testOut, err := runCommandOutput(ctx, repo, env, gantry, "remote", "test", "stub")
	if err != nil {
		return fmt.Errorf("remote test: %w", err)
	}
	if !strings.Contains(testOut, "ok, manager version") || !strings.Contains(testOut, "pinned, matches") {
		return fmt.Errorf("remote test output = %q", testOut)
	}
	listOut, err := runCommandOutput(ctx, repo, env, gantry, "ls", "-remote", "stub")
	if err != nil {
		return fmt.Errorf("ls -remote: %w", err)
	}
	if !strings.Contains(listOut, `no sandboxes on remote "stub"`) {
		return fmt.Errorf("ls -remote output = %q", listOut)
	}
	envOut, err := runCommandOutput(ctx, repo, append(env, "GANTRY_REMOTE=stub"), gantry, "ls")
	if err != nil {
		return fmt.Errorf("ls with GANTRY_REMOTE: %w", err)
	}
	if envOut != listOut {
		return fmt.Errorf("env dispatch output %q differs from flag dispatch %q", envOut, listOut)
	}
	// A local-only verb with an explicit -remote fails loudly.
	command := exec.CommandContext(ctx, gantry, "serve", "-remote", "stub")
	command.Dir = repo
	command.Env = env
	output, dispatchErr := command.CombinedOutput()
	if dispatchErr == nil || !strings.Contains(string(output), `-remote "stub" is not supported`) {
		return fmt.Errorf("serve -remote = %v %q, want loud local-only error", dispatchErr, output)
	}
	if _, err := runCommandOutput(ctx, repo, env, gantry, "remote", "rm", "stub"); err != nil {
		return fmt.Errorf("remote rm: %w", err)
	}
	return nil
}

// Failed batteries must stop the VM without deleting the daemon logs that
// explain errors intentionally summarized by the manager API (for example,
// guest-tool delivery/verification failures). The enclosing runner preserves
// this private workspace on failure; successful cleanup still deletes state.
func cleanupSandbox(ctx context.Context, client *apiClient, root, name string, failed bool) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	method, path := http.MethodDelete, "/v1/sandboxes/"+name
	if failed {
		method, path = http.MethodPost, path+"/stop"
	}
	status, _, _, err := client.do(cleanup, method, path, nil, nil)
	if err != nil || (status != http.StatusOK && status != http.StatusNotFound) {
		fmt.Fprintf(os.Stderr, "sandbox %s cleanup: status=%d error=%v\n", name, status, err)
	}
	if failed {
		logPath := filepath.Join(root, name, "daemon.log")
		fmt.Fprintln(os.Stderr, "sandbox log:", logPath)
		printLogTail(logPath, 80)
	}
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
	fmt.Fprintf(os.Stderr, "--- %s tail ---\n", filepath.Base(path))
	fmt.Fprintln(os.Stderr, strings.Join(parts, "\n"))
}
