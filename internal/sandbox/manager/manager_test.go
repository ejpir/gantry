package manager

import (
	"bytes"
	"github.com/ejpir/gantry/api/managerapi"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	service := newManagerService(stubLifecycle{})
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
	service := newManagerService(stubLifecycle{})
	body := []byte(`{"name":"alpha"}`)
	first, err := service.beginOperation("create", "alpha", "key-1", managerFingerprint("POST", "/v1/sandboxes", body))
	if err != nil || first.Replay {
		t.Fatalf("first begin = %+v err=%v", first, err)
	}
	finished := service.finishOperation(first.Owner, nil)
	if finished.State != "succeeded" {
		t.Fatalf("finished state = %q", finished.State)
	}
	second, err := service.beginOperation("create", "alpha", "key-1", managerFingerprint("POST", "/v1/sandboxes", body))
	if err != nil || !second.Replay || second.Operation.ID != first.Operation.ID || second.Phase != operationSucceeded {
		t.Fatalf("replay = %+v err=%v", second, err)
	}
	if _, err := service.beginOperation("delete", "alpha", "key-1", managerFingerprint("DELETE", "/v1/sandboxes/alpha", nil)); err == nil {
		t.Fatal("idempotency key reuse with a different request succeeded")
	}
}

func TestManagerDecodeRejectsUnknownAndOversizedRequests(t *testing.T) {
	service := newManagerService(stubLifecycle{})
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
	service := newManagerService(stubLifecycle{})
	for index := range managerMaxOperations + 20 {
		operation, err := service.beginOperation("test", "sandbox", "", managerFingerprint("POST", "/", []byte{byte(index)}))
		if err != nil || operation.Replay {
			t.Fatalf("begin %d: replay=%v err=%v", index, operation.Replay, err)
		}
		service.finishOperation(operation.Owner, nil)
	}
	records, order, _ := service.operationState.counts()
	if records > managerMaxOperations || order > managerMaxOperations {
		t.Fatalf("operations grew beyond bound: map=%d order=%d", records, order)
	}
}

func TestManagerEventsDropsSlowSubscriber(t *testing.T) {
	service := newManagerService(stubLifecycle{})
	_, events, cancel, ok := service.subscribe()
	if !ok {
		t.Fatal("subscribe failed")
	}
	defer cancel()
	for index := range managerEventBuffer + 1 {
		if _, err := service.beginOperation("event", "test", "", managerFingerprint("POST", "/", []byte{byte(index)})); err != nil {
			t.Fatal(err)
		}
	}
	for range events {
	}
	_, _, remaining := service.operationState.counts()
	if remaining != 0 {
		t.Fatalf("slow subscriber retained: %d", remaining)
	}
}

func TestManagerSocketPathUsesGantryParent(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GANTRY_MANAGER_SOCKET", "")
	t.Setenv("GANTRY_HOME", filepath.Join(root, "sandboxes"))
	if got, want := SocketPath(), filepath.Join(root, "manager.sock"); got != want {
		t.Fatalf("SocketPath() = %q, want %q", got, want)
	}
}

func TestServeManagerRefusesNonSocketEndpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manager.sock")
	if err := os.WriteFile(path, []byte("do not delete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := serveManager(path, stubLifecycle{}); err == nil || !strings.Contains(err.Error(), "non-socket") {
		t.Fatalf("serveManager error = %v, want non-socket refusal", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "do not delete" {
		t.Fatalf("endpoint was changed: contents=%q err=%v", contents, err)
	}
}

func TestManagerExecValidation(t *testing.T) {
	request := managerapi.ExecRequest{Argv: []string{"pwd"}, Cwd: "/workspace"}
	if err := validateManagerExec(&request); err != nil {
		t.Fatal(err)
	}
	if request.TimeoutSeconds != 30 || request.MaxOutputBytes != managerDefaultOutputBytes {
		t.Fatalf("defaults = timeout %d output %d", request.TimeoutSeconds, request.MaxOutputBytes)
	}
	for _, request := range []managerapi.ExecRequest{
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
