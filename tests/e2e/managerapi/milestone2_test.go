package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/remote"
)

func TestM2SSHFixtureCreatesWritableRootThroughRemoteCLI(t *testing.T) {
	t.Setenv("GANTRY_HOME", filepath.Join(t.TempDir(), "sandboxes"))
	const token = "m2-fixture-manager-token"
	requests := make(chan managerapi.CreateSandboxRequest, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sandboxes" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var request managerapi.CreateSandboxRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- request
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "fixture-start", Kind: "create", Sandbox: request.Name, State: "succeeded"})
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := remote.Add(remote.Profile{Name: "m2", URL: server.URL, CACert: string(ca)}, token); err != nil {
		t.Fatal(err)
	}
	opts := options{image: "/manager/image.erofs", kernel: "/manager/kernel", rootfs: "/manager/system.erofs"}
	args := m2LifecycleStartArgs("m2-lifecycle", opts)
	target, rest, err := remote.ExtractTarget(args, "must-not-be-used")
	if err != nil {
		t.Fatal(err)
	}
	if exit := remote.RunVerb(rest[0], target, rest[1:]); exit != 0 {
		t.Fatalf("fixture start exit=%d", exit)
	}
	select {
	case request := <-requests:
		if request.RW == nil || !*request.RW {
			t.Fatal("live SSH fixture disabled the share-based guest-tools delivery path")
		}
		if request.SSH || request.DevContainers {
			t.Fatal("fixture must exercise enabling SSH live, not at creation")
		}
		if request.Net == nil || *request.Net || request.OAuthBridge == nil || *request.OAuthBridge {
			t.Fatal("fixture enabled unrelated networking/OAuth features")
		}
		if request.Name != "m2-lifecycle" || request.Image != opts.image || request.Kernel != opts.kernel || request.Rootfs != opts.rootfs || request.MemoryMiB != 512 || request.CPUs != 1 {
			t.Fatalf("fixture options changed in transit: %+v", request)
		}
	default:
		t.Fatal("fixture did not reach the remote manager")
	}
}

func TestCleanupSandboxPreservesFailureDiagnostics(t *testing.T) {
	for _, failed := range []bool{false, true} {
		label := "success"
		if failed {
			label = "failure"
		}
		t.Run(label, func(t *testing.T) {
			root := t.TempDir()
			const name = "m2-lifecycle"
			dir := filepath.Join(root, name)
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(dir, "daemon.log")
			const diagnostic = "guest tools delivery failure detail\n"
			if err := os.WriteFile(logPath, []byte(diagnostic), 0o600); err != nil {
				t.Fatal(err)
			}
			requests := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- r.Method + " " + r.URL.Path
				if r.Method == http.MethodDelete {
					if err := os.RemoveAll(dir); err != nil {
						t.Error(err)
					}
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			client := &apiClient{http: server.Client(), baseURL: server.URL}
			// An overall timeout must not prevent the runner from stopping its VM.
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			cleanupSandbox(ctx, client, root, name, failed)
			want := "DELETE /v1/sandboxes/" + name
			if failed {
				want = "POST /v1/sandboxes/" + name + "/stop"
			}
			select {
			case got := <-requests:
				if got != want {
					t.Fatalf("cleanup = %s, want %s", got, want)
				}
			default:
				t.Fatal("cleanup did not reach manager")
			}
			data, err := os.ReadFile(logPath)
			if failed {
				if err != nil || string(data) != diagnostic {
					t.Fatalf("failed run lost diagnostics: %q, %v", data, err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatalf("successful run kept sandbox state: %v", err)
			}
		})
	}
}
