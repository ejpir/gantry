package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

type functionLifecycle struct {
	start  func(context.Context, lifecycle.StartRequest, lifecycle.Observer) (lifecycle.StartResult, error)
	stop   func(string) error
	delete func(string) error
	exec   func(context.Context, string, ExecRequest) (ExecResult, error)
}

func (f functionLifecycle) Start(ctx context.Context, request lifecycle.StartRequest, observer lifecycle.Observer) (lifecycle.StartResult, error) {
	if f.start == nil {
		panic("unexpected Lifecycle.Start")
	}
	return f.start(ctx, request, observer)
}

func (f functionLifecycle) Stop(name string) error {
	if f.stop == nil {
		panic("unexpected Lifecycle.Stop")
	}
	return f.stop(name)
}

func (f functionLifecycle) Delete(name string) error {
	if f.delete == nil {
		panic("unexpected Lifecycle.Delete")
	}
	return f.delete(name)
}

func (f functionLifecycle) Exec(ctx context.Context, name string, request ExecRequest) (ExecResult, error) {
	if f.exec == nil {
		panic("unexpected Lifecycle.Exec")
	}
	return f.exec(ctx, name, request)
}

func TestManagerRoutesLifecycleOperations(t *testing.T) {
	t.Setenv("GANTRY_HOME", filepath.Join(t.TempDir(), "sandboxes"))
	savedDir := layout.Dir("saved")
	if err := os.MkdirAll(savedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.WriteSandboxConfig(savedDir, config.RunConfig{MemMB: 512, VCPUs: 1}); err != nil {
		t.Fatal(err)
	}
	var requests []lifecycle.StartRequest
	var calls []string
	service := newManagerService(functionLifecycle{
		start: func(ctx context.Context, request lifecycle.StartRequest, _ lifecycle.Observer) (lifecycle.StartResult, error) {
			if ctx == nil {
				t.Fatal("missing operation context")
			}
			requests = append(requests, request)
			calls = append(calls, "start:"+request.Name)
			return lifecycle.StartResult{Name: request.Name, Warnings: []string{"cached warning"}}, nil
		},
		stop: func(name string) error {
			calls = append(calls, "stop:"+name)
			return fmt.Errorf("already stopped: %w", ErrNotRunning)
		},
		delete: func(name string) error { calls = append(calls, "delete:"+name); return nil },
	})
	create := managerRequest(t, service, http.MethodPost, "/v1/sandboxes",
		`{"name":"created","image":"example.test/app","memoryMiB":768,"cpus":2,"processIsolation":"off","secretNames":["CREATE_TOKEN"]}`, nil)
	if create.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", create.Code, create.Body.String())
	}
	var operation managerOperation
	if err := json.Unmarshal(create.Body.Bytes(), &operation); err != nil {
		t.Fatal(err)
	}
	if operation.State != "succeeded" || !reflect.DeepEqual(operation.Warnings, []string{"cached warning"}) {
		t.Fatalf("operation = %+v", operation)
	}
	for _, action := range []struct{ method, path string }{
		{http.MethodPost, "/v1/sandboxes/saved/start"},
		{http.MethodPost, "/v1/sandboxes/saved/stop"},
		{http.MethodDelete, "/v1/sandboxes/saved"},
	} {
		response := managerRequest(t, service, action.method, action.path, "", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("%s = %d %s", action.path, response.Code, response.Body.String())
		}
	}
	if !reflect.DeepEqual(calls, []string{"start:created", "start:saved", "stop:saved", "delete:saved"}) {
		t.Fatalf("calls=%v", calls)
	}
	if len(requests) != 2 {
		t.Fatalf("requests=%+v", requests)
	}
	created := requests[0]
	if created.Name != "created" || created.Mode != lifecycle.Create || !created.CachedOnly ||
		created.Options.Image != "example.test/app" || created.Options.MemMB != 768 || created.Options.VCPUs != 2 ||
		created.Options.ProcessIsolation != "off" || !created.Options.Explicit.Memory || !created.Options.Explicit.CPUs ||
		!created.Options.Explicit.RW || created.Options.RW || !reflect.DeepEqual(created.Options.Secrets, []string{"CREATE_TOKEN"}) {
		t.Fatalf("create request=%+v", created)
	}
	if requests[1].Name != "saved" || requests[1].Mode != lifecycle.Resume {
		t.Fatalf("resume request=%+v", requests[1])
	}
}

func TestManagerMapsLifecycleErrors(t *testing.T) {
	t.Setenv("GANTRY_HOME", filepath.Join(t.TempDir(), "sandboxes"))
	stopCalls := 0
	service := newManagerService(functionLifecycle{
		stop: func(name string) error {
			stopCalls++
			if name != "missing" {
				t.Fatalf("Stop name = %q", name)
			}
			return fmt.Errorf("wrapped: %w", ErrNotRunning)
		},
	})
	response := managerRequest(t, service, http.MethodPost, "/v1/sandboxes/missing/stop", "", nil)
	if response.Code != http.StatusConflict || stopCalls != 1 {
		t.Fatalf("missing stop = %d %s calls=%d", response.Code, response.Body.String(), stopCalls)
	}

	for _, test := range []struct {
		name   string
		err    error
		status int
	}{
		{name: "timeout", err: ErrExecTimeout, status: http.StatusRequestTimeout},
		{name: "output limit", err: ErrExecOutputLimit, status: http.StatusRequestEntityTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			execCalls := 0
			service := newManagerService(functionLifecycle{
				exec: func(_ context.Context, name string, request ExecRequest) (ExecResult, error) {
					execCalls++
					if name != "target" || !reflect.DeepEqual(request.Args, []string{"true"}) {
						t.Fatalf("Exec call = name %q request %+v", name, request)
					}
					return ExecResult{}, fmt.Errorf("wrapped: %w", test.err)
				},
			})
			response := managerRequest(t, service, http.MethodPost, "/v1/sandboxes/target/exec", `{"argv":["true"]}`, nil)
			if response.Code != test.status || execCalls != 1 {
				t.Fatalf("exec = %d %s calls=%d, want status %d", response.Code, response.Body.String(), execCalls, test.status)
			}
		})
	}
}

func TestManagerRoutesExecResult(t *testing.T) {
	wantRequest := ExecRequest{
		Args: []string{"sh", "-c", "exit 7"}, Cwd: "/workspace", Stdin: "input",
		Timeout: 9 * time.Second, MaxOutputBytes: 1234,
	}
	service := newManagerService(functionLifecycle{
		exec: func(ctx context.Context, name string, request ExecRequest) (ExecResult, error) {
			if ctx == nil || name != "target" || !reflect.DeepEqual(request, wantRequest) {
				t.Fatalf("Exec call = context %v name %q request %+v", ctx, name, request)
			}
			return ExecResult{ExitCode: 7, Output: []byte("captured"), Truncated: true}, nil
		},
	})
	response := managerRequest(t, service, http.MethodPost, "/v1/sandboxes/target/exec",
		`{"argv":["sh","-c","exit 7"],"cwd":"/workspace","stdin":"input","timeoutSeconds":9,"maxOutputBytes":1234}`, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("exec = %d %s", response.Code, response.Body.String())
	}
	var result managerExecResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 7 || result.Output != "captured" || !result.Truncated {
		t.Fatalf("exec result = %+v", result)
	}
}
