package sandbox

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func managerRequest(t *testing.T, service *managerService, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	service.handler().ServeHTTP(response, request)
	return response
}

func TestManagerHealthAndOpenAPI(t *testing.T) {
	service := newManagerService()
	health := managerRequest(t, service, http.MethodGet, "/v1/health", "", nil)
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"version":"v1"`) {
		t.Fatalf("health = %d %s", health.Code, health.Body.String())
	}
	spec := managerRequest(t, service, http.MethodGet, "/v1/openapi.yaml", "", nil)
	if spec.Code != http.StatusOK || !strings.Contains(spec.Body.String(), "/v1/sandboxes/{name}/exec:") {
		t.Fatalf("OpenAPI = %d %s", spec.Code, spec.Body.String())
	}
}

func TestManagerIdempotencyReplaysAndRejectsMismatch(t *testing.T) {
	service := newManagerService()
	body := []byte(`{"name":"alpha"}`)
	first, replay, err := service.beginOperation("create", "alpha", "key-1", managerFingerprint("POST", "/v1/sandboxes", body))
	if err != nil || replay {
		t.Fatalf("first begin = %+v replay=%v err=%v", first, replay, err)
	}
	finished := service.finishOperation(first.ID, nil)
	if finished.State != "succeeded" {
		t.Fatalf("finished state = %q", finished.State)
	}
	second, replay, err := service.beginOperation("create", "alpha", "key-1", managerFingerprint("POST", "/v1/sandboxes", body))
	if err != nil || !replay || second.ID != first.ID || second.State != "succeeded" {
		t.Fatalf("replay = %+v replay=%v err=%v", second, replay, err)
	}
	if _, _, err := service.beginOperation("delete", "alpha", "key-1", managerFingerprint("DELETE", "/v1/sandboxes/alpha", nil)); err == nil {
		t.Fatal("idempotency key reuse with a different request succeeded")
	}
}

func TestManagerCreateRejectsUncachedImageWithoutNetwork(t *testing.T) {
	t.Setenv("GANTRY_HOME", filepath.Join(t.TempDir(), "sandboxes"))
	t.Setenv("GANTRY_IMAGES", t.TempDir())
	dir := t.TempDir()
	rootfs := filepath.Join(dir, "rootfs.erofs")
	// Resolution reaches the cache-only miss only after kernel architecture
	// detection. Use a minimal x86-64 ELF header so the test is independent of
	// the host executable format (PE on Windows, Mach-O on macOS).
	kernel := filepath.Join(dir, "kernel")
	kernelHeader := make([]byte, 0x40)
	copy(kernelHeader, "\x7fELF")
	kernelHeader[18] = 62 // EM_X86_64, little endian.
	if err := os.WriteFile(kernel, kernelHeader, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootfs, []byte("rootfs"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := managerCreateRequest{Name: "offline", Image: "example.invalid/app:latest", Kernel: kernel, Rootfs: rootfs, RW: boolPointer(false), Net: boolPointer(false)}
	encoded, _ := json.Marshal(request)
	response := managerRequest(t, newManagerService(), http.MethodPost, "/v1/sandboxes", string(encoded), nil)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "gantry image pull") {
		t.Fatalf("create = %d %s", response.Code, response.Body.String())
	}
}

func TestManagerDecodeRejectsUnknownAndOversizedRequests(t *testing.T) {
	service := newManagerService()
	unknown := managerRequest(t, service, http.MethodPost, "/v1/sandboxes/test/exec", `{"argv":["true"],"secret":"value"}`, nil)
	if unknown.Code != http.StatusBadRequest || !strings.Contains(unknown.Body.String(), "unknown field") {
		t.Fatalf("unknown field = %d %s", unknown.Code, unknown.Body.String())
	}
	oversized := `{"argv":["true"],"stdin":"` + strings.Repeat("x", managerMaxRequestBytes) + `"}`
	response := managerRequest(t, service, http.MethodPost, "/v1/sandboxes/test/exec", oversized, nil)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "exceeds") {
		t.Fatalf("oversized = %d %s", response.Code, response.Body.String())
	}
}

func TestManagerOperationsAreBounded(t *testing.T) {
	service := newManagerService()
	for index := range managerMaxOperations + 20 {
		operation, replay, err := service.beginOperation("test", "sandbox", "", managerFingerprint("POST", "/", []byte{byte(index)}))
		if err != nil || replay {
			t.Fatalf("begin %d: replay=%v err=%v", index, replay, err)
		}
		service.finishOperation(operation.ID, nil)
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(service.operations) > managerMaxOperations || len(service.operationOrder) > managerMaxOperations {
		t.Fatalf("operations grew beyond bound: map=%d order=%d", len(service.operations), len(service.operationOrder))
	}
}

func TestManagerEventsDropsSlowSubscriber(t *testing.T) {
	service := newManagerService()
	_, events, cancel, ok := service.subscribe()
	if !ok {
		t.Fatal("subscribe failed")
	}
	defer cancel()
	for index := range managerEventBuffer + 1 {
		operation := &managerOperation{ID: "event", Sandbox: "test", State: "running", Created: time.Now(), Updated: time.Now()}
		service.mu.Lock()
		service.publishLocked("operation", operation)
		service.mu.Unlock()
		_ = index
	}
	for range events {
	}
	service.mu.Lock()
	remaining := len(service.subscribers)
	service.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("slow subscriber retained: %d", remaining)
	}
}

func TestManagerSocketPathUsesGantryParent(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GANTRY_MANAGER_SOCKET", "")
	t.Setenv("GANTRY_HOME", filepath.Join(root, "sandboxes"))
	if got, want := ManagerSocketPath(), filepath.Join(root, "manager.sock"); got != want {
		t.Fatalf("ManagerSocketPath() = %q, want %q", got, want)
	}
}

func TestServeManagerRefusesNonSocketEndpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manager.sock")
	if err := os.WriteFile(path, []byte("do not delete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := serveManager(path); err == nil || !strings.Contains(err.Error(), "non-socket") {
		t.Fatalf("serveManager error = %v, want non-socket refusal", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "do not delete" {
		t.Fatalf("endpoint was changed: contents=%q err=%v", contents, err)
	}
}

func TestManagerExecValidation(t *testing.T) {
	request := managerExecRequest{Argv: []string{"pwd"}, Cwd: "/workspace"}
	if err := validateManagerExec(&request); err != nil {
		t.Fatal(err)
	}
	if request.TimeoutSeconds != 30 || request.MaxOutputBytes != managerDefaultOutputBytes {
		t.Fatalf("defaults = timeout %d output %d", request.TimeoutSeconds, request.MaxOutputBytes)
	}
	for _, request := range []managerExecRequest{
		{},
		{Argv: []string{"true"}, Cwd: "relative"},
		{Argv: []string{"true"}, TimeoutSeconds: 3601},
		{Argv: []string{"true"}, MaxOutputBytes: managerMaximumOutputBytes + 1},
	} {
		if err := validateManagerExec(&request); err == nil {
			t.Fatalf("invalid request accepted: %+v", request)
		}
	}
}

func TestManagerFingerprintIncludesMethodPathAndBody(t *testing.T) {
	base := managerFingerprint("POST", "/a", []byte("body"))
	for _, changed := range []string{
		managerFingerprint("DELETE", "/a", []byte("body")),
		managerFingerprint("POST", "/b", []byte("body")),
		managerFingerprint("POST", "/a", []byte("other")),
	} {
		if bytes.Equal([]byte(base), []byte(changed)) {
			t.Fatal("fingerprint did not include the full request identity")
		}
	}
}

func boolPointer(value bool) *bool { return &value }
