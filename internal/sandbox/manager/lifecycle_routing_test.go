package manager

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/secret"
)

type functionLifecycle struct {
	resolve func(*config.RunFlags, *flag.FlagSet) (config.RunConfig, []string, error)
	launch  func(string, config.RunConfig, map[string]secret.Value, bool, io.Writer, io.Writer) int
	stop    func(string) error
	delete  func(string) error
	exec    func(context.Context, string, ExecRequest) (ExecResult, error)
}

func (f functionLifecycle) Resolve(flags *config.RunFlags, fs *flag.FlagSet) (config.RunConfig, []string, error) {
	if f.resolve == nil {
		panic("unexpected Lifecycle.Resolve")
	}
	return f.resolve(flags, fs)
}

func (f functionLifecycle) Launch(name string, cfg config.RunConfig, secrets map[string]secret.Value, replace bool, stdout, stderr io.Writer) int {
	if f.launch == nil {
		panic("unexpected Lifecycle.Launch")
	}
	return f.launch(name, cfg, secrets, replace, stdout, stderr)
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
	t.Setenv("CREATE_TOKEN", "create-value")
	t.Setenv("START_TOKEN", "start-value")

	saved := config.RunConfig{
		Image: "saved.erofs", MemMB: 512, VCPUs: 1,
		SecretNames: []string{"START_TOKEN"},
	}
	savedDir := layout.Dir("saved")
	if err := os.MkdirAll(savedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.WriteSandboxConfig(savedDir, saved); err != nil {
		t.Fatal(err)
	}

	resolved := config.RunConfig{
		Image: "resolved.erofs", MemMB: 768, VCPUs: 2,
		SecretNames: []string{"CREATE_TOKEN"}, ProcessIsolation: "off",
	}
	type launchCall struct {
		name    string
		cfg     config.RunConfig
		secrets map[string]secret.Value
		replace bool
	}
	var calls []string
	var launches []launchCall
	lifecycle := functionLifecycle{
		resolve: func(flags *config.RunFlags, _ *flag.FlagSet) (config.RunConfig, []string, error) {
			calls = append(calls, "resolve")
			if flags.Name != "created" || *flags.Image != "example.test/app" ||
				*flags.MemMB != 768 || *flags.VCPUs != 2 || *flags.ProcessIsolation != "off" {
				t.Fatalf("create flags were not routed: %+v", flags)
			}
			if got := flags.Secrets.List(); !reflect.DeepEqual(got, []string{"CREATE_TOKEN"}) {
				t.Fatalf("create secrets = %v", got)
			}
			return resolved, []string{"cached warning"}, nil
		},
		launch: func(name string, cfg config.RunConfig, values map[string]secret.Value, replace bool, stdout, stderr io.Writer) int {
			calls = append(calls, "launch:"+name)
			copyValues := make(map[string]secret.Value, len(values))
			for key, value := range values {
				copyValues[key] = value
			}
			launches = append(launches, launchCall{name: name, cfg: cfg, secrets: copyValues, replace: replace})
			if stdout == nil || stderr == nil {
				t.Fatal("Launch received nil output writer")
			}
			return 0
		},
		stop: func(name string) error {
			calls = append(calls, "stop:"+name)
			return fmt.Errorf("already stopped: %w", ErrNotRunning)
		},
		delete: func(name string) error {
			calls = append(calls, "delete:"+name)
			return nil
		},
	}
	service := newManagerService(lifecycle)

	create := managerRequest(t, service, http.MethodPost, "/v1/sandboxes",
		`{"name":"created","image":"example.test/app","memoryMiB":768,"cpus":2,"processIsolation":"off","secretNames":["CREATE_TOKEN"]}`, nil)
	if create.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", create.Code, create.Body.String())
	}
	var createOperation managerOperation
	if err := json.Unmarshal(create.Body.Bytes(), &createOperation); err != nil {
		t.Fatal(err)
	}
	if createOperation.State != "succeeded" || !reflect.DeepEqual(createOperation.Warnings, []string{"cached warning"}) {
		t.Fatalf("create operation = %+v", createOperation)
	}

	start := managerRequest(t, service, http.MethodPost, "/v1/sandboxes/saved/start", "", nil)
	if start.Code != http.StatusOK {
		t.Fatalf("start = %d %s", start.Code, start.Body.String())
	}
	stop := managerRequest(t, service, http.MethodPost, "/v1/sandboxes/saved/stop", "", nil)
	if stop.Code != http.StatusOK {
		t.Fatalf("idempotent stop = %d %s", stop.Code, stop.Body.String())
	}
	deleted := managerRequest(t, service, http.MethodDelete, "/v1/sandboxes/saved", "", nil)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", deleted.Code, deleted.Body.String())
	}

	wantCalls := []string{"resolve", "launch:created", "launch:saved", "stop:saved", "delete:saved"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("lifecycle calls = %v, want %v", calls, wantCalls)
	}
	if len(launches) != 2 {
		t.Fatalf("launch calls = %+v", launches)
	}
	if call := launches[0]; call.name != "created" || !call.replace || !reflect.DeepEqual(call.cfg, resolved) ||
		call.secrets["CREATE_TOKEN"].Raw() != "create-value" {
		t.Fatalf("create launch = %+v", call)
	}
	if call := launches[1]; call.name != "saved" || call.replace || !reflect.DeepEqual(call.cfg, saved) ||
		call.secrets["START_TOKEN"].Raw() != "start-value" {
		t.Fatalf("start launch = %+v", call)
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
