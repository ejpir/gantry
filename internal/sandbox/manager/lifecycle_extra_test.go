package manager

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func extraSandbox(t *testing.T, name string) string {
	t.Helper()
	dir := layout.Dir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.WriteSandboxConfig(dir, config.RunConfig{MemMB: 512, VCPUs: 1, ProcessIsolation: "required", Runtime: "crun", SSH: true}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestConfigureStoppedPreservesOmissionFalseAndReplay(t *testing.T) {
	t.Setenv("GANTRY_HOME", filepath.Join(t.TempDir(), "sandboxes"))
	dir := extraSandbox(t, "dev")
	service := newManagerService(stubLifecycle{})
	defer service.cancel()
	body := `{"ssh":false,"memoryMiB":768,"cpus":2}`
	headers := map[string]string{"Idempotency-Key": "configure-dev"}
	first := managerRequest(t, service, http.MethodPatch, "/v1/sandboxes/dev", body, headers)
	if first.Code != http.StatusOK {
		t.Fatalf("configure=%d %s", first.Code, first.Body.String())
	}
	var operation managerapi.Operation
	if err := json.Unmarshal(first.Body.Bytes(), &operation); err != nil {
		t.Fatal(err)
	}
	if operation.Configure == nil || operation.Configure.RestartRequired {
		t.Fatal("stopped configure result missing/incorrect")
	}
	cfg, err := config.ReadSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSH || cfg.MemMB != 768 || cfg.VCPUs != 2 || cfg.ProcessIsolation != "required" {
		t.Fatalf("partial update changed omitted fields: %+v", cfg)
	}
	cfg.MemMB = 1024
	if err := config.WriteSandboxConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	replay := managerRequest(t, service, http.MethodPatch, "/v1/sandboxes/dev", body, headers)
	if replay.Code != http.StatusOK || replay.Body.String() != first.Body.String() {
		t.Fatalf("replay changed result: %s", replay.Body.String())
	}
	cfg, err = config.ReadSandboxConfig(dir)
	if err != nil || cfg.MemMB != 1024 {
		t.Fatal("idempotent retry performed a second mutation")
	}
	conflict := managerRequest(t, service, http.MethodPatch, "/v1/sandboxes/dev", `{"ssh":true}`, headers)
	if conflict.Code != http.StatusConflict {
		t.Fatal("key reused for another request")
	}
	copy, _ := service.operation(operation.ID)
	copy.Configure.RestartRequired = true
	stored, _ := service.operation(operation.ID)
	if stored.Configure.RestartRequired {
		t.Fatal("operation result aliases private state")
	}
}

func TestConfigureValidationAndLaunchLockAreNonMutating(t *testing.T) {
	t.Setenv("GANTRY_HOME", filepath.Join(t.TempDir(), "sandboxes"))
	dir := extraSandbox(t, "dev")
	service := newManagerService(stubLifecycle{})
	defer service.cancel()
	before, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{}`, `{"ssh":null}`, `{"memoryMiB":0}`, `{"cpus":0}`, `{"cpus":-1}`, `{"processIsolation":"bad"}`, `{"ssh":true,"secret":"no"}`, `{"ssh":true} {}`} {
		r := managerRequest(t, service, http.MethodPatch, "/v1/sandboxes/dev", body, nil)
		if r.Code != http.StatusBadRequest {
			t.Errorf("accepted %s: %d %s", body, r.Code, r.Body.String())
		}
	}
	lock, err := layout.HoldLaunchLock("dev")
	if err != nil {
		t.Fatal(err)
	}
	r := managerRequest(t, service, http.MethodPatch, "/v1/sandboxes/dev", `{"ssh":false}`, nil)
	_ = lock.Close()
	if r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "launching") {
		t.Fatalf("launch lock ignored: %d %s", r.Code, r.Body.String())
	}
	after, _ := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if string(before) != string(after) {
		t.Fatal("refused update changed configuration")
	}
	r = managerRequest(t, service, http.MethodPatch, "/v1/sandboxes/missing", `{"ssh":true}`, nil)
	if r.Code != http.StatusNotFound {
		t.Fatalf("missing=%d", r.Code)
	}
	if _, err := os.Stat(layout.Dir("missing")); !os.IsNotExist(err) {
		t.Fatal("configure manufactured a missing sandbox")
	}
}

func TestConfigureLiveDelegatesToDaemonAndReportsRestart(t *testing.T) {
	root, err := os.MkdirTemp("", "gmc-")
	if err != nil {
		t.Fatal(err)
	}
	// Avoid the long nested t.TempDir name in AF_UNIX socket paths.
	if len(filepath.Join(root, "dev", "ctl.sock")) > 100 {
		_ = os.RemoveAll(root)
		t.Skip("temporary path exceeds Unix socket budget")
	}
	defer func() { _ = os.RemoveAll(root) }()
	t.Setenv("GANTRY_HOME", root)
	dir := extraSandbox(t, "dev")
	lock, err := layout.HoldLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := os.WriteFile(filepath.Join(dir, "vmm.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(dir, "ctl.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	captured := make(chan controlproto.Request, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		var request controlproto.Request
		line, err := controlproto.ReadBoundedLine(bufio.NewReader(conn), controlproto.MaxRequestBytes)
		if err == nil && json.Unmarshal(line, &request) == nil {
			captured <- request
			_, _ = fmt.Fprintln(conn, `{"ok":true,"restart_required":true}`)
		}
	}()
	service := newManagerService(stubLifecycle{})
	defer service.cancel()
	r := managerRequest(t, service, http.MethodPatch, "/v1/sandboxes/dev", `{"ssh":false,"memoryMiB":1024}`, nil)
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"restartRequired":true`) {
		t.Fatalf("live result=%d %s", r.Code, r.Body.String())
	}
	select {
	case req := <-captured:
		if req.Op != "sandbox.configure" || req.Configure == nil || req.Configure.SSH == nil || *req.Configure.SSH || req.Configure.VCPUs != nil || *req.Configure.MemMB != 1024 {
			t.Fatalf("daemon request=%+v", req)
		}
	case <-time.After(time.Second):
		t.Fatal("no daemon request")
	}
}

type runLifecycleStub struct {
	stubLifecycle
	run func(context.Context, managerapi.RunVMRequest) (managerapi.ExecResult, error)
}

func (s runLifecycleStub) RunVM(ctx context.Context, r managerapi.RunVMRequest) (managerapi.ExecResult, error) {
	return s.run(ctx, r)
}

func TestRunVMDefaultsResultBoundsReplayAndValidation(t *testing.T) {
	var calls atomic.Int32
	service := newManagerService(runLifecycleStub{run: func(ctx context.Context, r managerapi.RunVMRequest) (managerapi.ExecResult, error) {
		calls.Add(1)
		if r.MemoryMiB != 512 || r.CPUs != 1 || r.TimeoutSeconds != 300 || r.NetworkVFKIT == nil || !*r.NetworkVFKIT {
			t.Errorf("defaults missing: %+v", r)
		}
		return managerapi.ExecResult{ExitCode: 7, Output: "123456789"}, nil
	}})
	defer service.cancel()
	body := `{"kernel":"/k","rootfs":"/r","maxOutputBytes":4}`
	headers := map[string]string{"Idempotency-Key": "raw-run"}
	first := managerRequest(t, service, http.MethodPost, "/v1/run", body, headers)
	if first.Code != http.StatusOK {
		t.Fatalf("run=%d %s", first.Code, first.Body.String())
	}
	var operation managerapi.Operation
	if err := json.Unmarshal(first.Body.Bytes(), &operation); err != nil {
		t.Fatal(err)
	}
	if operation.Kind != "run" || operation.Sandbox != "" || operation.Run == nil || operation.Run.Output != "1234" || !operation.Run.Truncated || operation.Run.ExitCode != 7 {
		t.Fatalf("result=%+v", operation)
	}
	replay := managerRequest(t, service, http.MethodPost, "/v1/run", body, headers)
	if first.Body.String() != replay.Body.String() || calls.Load() != 1 {
		t.Fatal("replay launched a second VM")
	}
	operation.Run.Output = "changed"
	stored, _ := service.operation(operation.ID)
	if stored.Run.Output != "1234" {
		t.Fatal("output not isolated")
	}
	for _, bad := range []string{`{}`, `{"kernel":"/k"}`, `{"kernel":"/k","rootfs":"/r","timeoutSeconds":0}`, `{"kernel":"/k","rootfs":"/r","maxOutputBytes":65537}`, `{"kernel":"/k","rootfs":"/r","argv":["sh"]}`} {
		r := managerRequest(t, service, http.MethodPost, "/v1/run", bad, nil)
		if r.Code != http.StatusBadRequest {
			t.Fatalf("bad body accepted: %d %s", r.Code, r.Body.String())
		}
	}
	if calls.Load() != 1 {
		t.Fatal("invalid body reached raw VM service")
	}
}

func TestOrganizationWidePolicyDisablesRawVMRun(t *testing.T) {
	var calls atomic.Int32
	service := newManagerService(runLifecycleStub{run: func(context.Context, managerapi.RunVMRequest) (managerapi.ExecResult, error) {
		calls.Add(1)
		return managerapi.ExecResult{}, nil
	}})
	service.organizationPolicy = policytest.Signed(t, policy.Profile{})
	response := managerRequest(t, service, http.MethodPost, "/v1/run", `{"kernel":"/k","rootfs":"/r"}`, nil)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "disabled while an organization-wide policy feed is active") {
		t.Fatalf("raw run = %d %s", response.Code, response.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatal("organization-managed request reached raw VM backend")
	}
}

func TestRunVMCancellationAndConcurrentReplay(t *testing.T) {
	entered := make(chan struct{})
	var calls atomic.Int32
	service := newManagerService(runLifecycleStub{run: func(ctx context.Context, _ managerapi.RunVMRequest) (managerapi.ExecResult, error) {
		calls.Add(1)
		close(entered)
		<-ctx.Done()
		return managerapi.ExecResult{ExitCode: 130}, nil
	}})
	defer service.cancel()
	body := `{"kernel":"/k","rootfs":"/r"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/run", strings.NewReader(body))
	request.Header.Set("Idempotency-Key", "active")
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { service.handler().ServeHTTP(response, request); close(done) }()
	<-entered
	replay := managerRequest(t, service, http.MethodPost, "/v1/run", body, map[string]string{"Idempotency-Key": "active"})
	if replay.Code != http.StatusAccepted || calls.Load() != 1 {
		t.Fatal("concurrent retry launched twice")
	}
	service.cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel raw VM")
	}
	if !strings.Contains(response.Body.String(), `"exitCode":130`) {
		t.Fatalf("canceled result: %s", response.Body.String())
	}
}
