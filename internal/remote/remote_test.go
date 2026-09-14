package remote

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ejpir/gantry/api/managerapi"
)

const testToken = "test-token-0123456789abcdef"

// testHome isolates the profile store in a GANTRY_HOME-shaped temp tree.
func testHome(t *testing.T) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "sandboxes")
	t.Setenv("GANTRY_HOME", home)
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	return home
}

func addTestProfile(t *testing.T, name string) Profile {
	t.Helper()
	profile := Profile{Name: name, URL: "https://192.0.2.10:8443"}
	if err := Add(profile, testToken); err != nil {
		t.Fatal(err)
	}
	return profile
}

func TestStoreRoundTrip(t *testing.T) {
	testHome(t)
	added := addTestProfile(t, "cloud")

	profiles, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0] != added {
		t.Fatalf("List = %+v, want %+v", profiles, added)
	}
	profile, token, err := Load("cloud")
	if err != nil {
		t.Fatal(err)
	}
	if profile != added || token != testToken {
		t.Fatalf("Load = %+v, %q", profile, token)
	}

	// Unix mode bits protect both files. Windows token ACL validation happens
	// in Load above and is covered directly by the Windows security test.
	if runtime.GOOS != "windows" {
		for _, path := range []string{storePath(), tokenPath("cloud")} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("%s mode = %04o, want 0600", path, info.Mode().Perm())
			}
		}
	}

	if err := Remove("cloud"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load("cloud"); err == nil || !strings.Contains(err.Error(), "unknown remote") {
		t.Fatalf("Load after remove = %v, want unknown remote", err)
	}
	if _, err := os.Lstat(tokenPath("cloud")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("token file survives remove: %v", err)
	}
	if err := Remove("cloud"); err == nil {
		t.Fatal("second Remove succeeded")
	}
}

func TestStoreRejectsDuplicatesAndUnknownListsConfigured(t *testing.T) {
	testHome(t)
	addTestProfile(t, "a")
	addTestProfile(t, "b")
	if err := Add(Profile{Name: "a", URL: "https://192.0.2.11"}, testToken); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate Add = %v, want already exists", err)
	}
	_, _, err := Load("zz")
	if err == nil || !strings.Contains(err.Error(), "configured: a, b") {
		t.Fatalf("Load unknown = %v, want configured names", err)
	}
}

func TestProfileValidation(t *testing.T) {
	testHome(t)
	for _, profile := range []Profile{
		{Name: "bad name!", URL: "https://192.0.2.10"},
		{Name: "ok", URL: "http://192.0.2.10"},       // plaintext refused
		{Name: "ok", URL: "https://192.0.2.10/path"}, // API root only
		{Name: "ok", URL: "https://user@192.0.2.10"}, // no embedded credentials
		{Name: "ok", URL: "https://192.0.2.10?x=y"},  // no query
		{Name: "ok", URL: "https://192.0.2.10", Fingerprint: "sha256:zz"},
	} {
		if err := Add(profile, testToken); err == nil {
			t.Errorf("Add(%+v) succeeded, want validation error", profile)
		}
	}
	if err := Add(Profile{Name: "ok", URL: "https://192.0.2.10"}, "short"); err == nil {
		t.Error("short token accepted")
	}
	if err := Add(Profile{Name: "ok", URL: "https://192.0.2.10"}, "has space in token"); err == nil {
		t.Error("token with spaces accepted")
	}
}

func TestLoadTokenRefusesGroupReadable(t *testing.T) {
	testHome(t)
	addTestProfile(t, "cloud")
	if runtime.GOOS == "windows" {
		// os.Chmod does not alter the Windows DACL. The equivalent ACL
		// rejection is covered by TestLoadTokenRefusesPermissiveWindowsACL.
		return
	}
	path := tokenPath("cloud")
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	_, _, err := Load("cloud")
	if err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("Load with 0640 token = %v, want chmod hint", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load("cloud"); err != nil {
		t.Fatalf("Load with 0600 token = %v", err)
	}
}

func TestLoadMissingTokenExplains(t *testing.T) {
	testHome(t)
	addTestProfile(t, "cloud")
	if err := os.Remove(tokenPath("cloud")); err != nil {
		t.Fatal(err)
	}
	_, _, err := Load("cloud")
	if err == nil || !strings.Contains(err.Error(), "no token for remote") {
		t.Fatalf("Load without token = %v, want re-add hint", err)
	}
}

// stubManager serves a minimal manager API for client tests. The token is
// checked on every request, mirroring the real manager's middleware.
func stubManager(t *testing.T, handler http.Handler) (*httptest.Server, Profile) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(managerapi.ErrorResponse{Error: "access denied"})
			return
		}
		handler.ServeHTTP(w, r)
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	leaf := server.Certificate()
	sum := sha256.Sum256(leaf.Raw)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("test CA does not parse")
	}
	profile := Profile{
		Name:        "stub",
		URL:         server.URL,
		Fingerprint: "sha256:" + hex.EncodeToString(sum[:]),
		CACert:      string(caPEM),
	}
	return server, profile
}

func TestClientTLSVerificationModes(t *testing.T) {
	_, profile := stubManager(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(managerapi.Health{OK: true, Version: "test"})
	}))

	// CA + correct pin: served.
	client, err := Dial(profile, testToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Health(t.Context()); err != nil {
		t.Fatalf("Health with CA+pin = %v", err)
	}
	live, ok := client.LiveFingerprint()
	if !ok || live != profile.Fingerprint {
		t.Fatalf("LiveFingerprint = %q %v, want %q", live, ok, profile.Fingerprint)
	}

	// CA without a pin: served.
	client, err = Dial(Profile{Name: profile.Name, URL: profile.URL, CACert: profile.CACert}, testToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Health(t.Context()); err != nil {
		t.Fatalf("Health with CA only = %v", err)
	}

	// Wrong pin: the handshake must fail even though the chain verifies.
	wrong := Profile{Name: profile.Name, URL: profile.URL, CACert: profile.CACert,
		Fingerprint: "sha256:" + strings.Repeat("0", 64)}
	client, err = Dial(wrong, testToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Health(t.Context()); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("Health with wrong pin = %v, want fingerprint mismatch", err)
	}

	// No CA at all: untrusted, with the self-signed hint.
	client, err = Dial(Profile{Name: profile.Name, URL: profile.URL}, testToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Health(t.Context()); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("Health without CA = %v, want not-trusted hint", err)
	}

	// The token goes on every request; a wrong token is the manager's 403.
	client, err = Dial(profile, "wrong-token-value-here")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Health(t.Context()); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("Health with wrong token = %v, want access denied", err)
	}
}

func TestClientLifecycleCalls(t *testing.T) {
	var created managerapi.CreateSandboxRequest
	operations := 0
	_, profile := stubManager(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes":
			_ = json.NewEncoder(w).Encode(map[string]any{"sandboxes": []managerapi.Sandbox{
				{Name: "dev", State: "running", PID: 42, Image: "alpine"},
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes":
			if r.Header.Get("Idempotency-Key") == "" {
				t.Error("create without Idempotency-Key")
			}
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "op-1", Kind: "create", Sandbox: created.Name, State: "succeeded", Warnings: []string{"w1"}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/dev/start":
			operations++
			_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "op-2", Kind: "start", State: "running"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/operations/op-2":
			operations++
			_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "op-2", Kind: "start", State: "succeeded"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/dev/stop":
			_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "op-3", Kind: "stop", State: "succeeded"})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sandboxes/dev":
			_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "op-4", Kind: "delete", State: "succeeded"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/dev/exec":
			var request managerapi.ExecRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			if len(request.Argv) == 0 {
				t.Error("exec without argv")
			}
			_ = json.NewEncoder(w).Encode(managerapi.ExecResult{ExitCode: 3, Output: "out:" + strings.Join(request.Argv, ","), Truncated: true})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/dev":
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(managerapi.ErrorResponse{Error: "sandbox not found"})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(managerapi.ErrorResponse{Error: "no such route"})
		}
	}))
	client, err := Dial(profile, testToken)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()

	sandboxes, err := client.ListSandboxes(ctx)
	if err != nil || len(sandboxes) != 1 || sandboxes[0].Name != "dev" || sandboxes[0].PID != 42 {
		t.Fatalf("ListSandboxes = %+v, %v", sandboxes, err)
	}

	rw := true
	operation, err := client.CreateSandbox(ctx, managerapi.CreateSandboxRequest{
		Name: "dev", Image: "alpine", RW: &rw, MemoryMiB: 512, SecretNames: []string{"GH"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if operation.State != "succeeded" || len(operation.Warnings) != 1 {
		t.Fatalf("CreateSandbox = %+v", operation)
	}
	if created.Name != "dev" || created.Image != "alpine" || created.RW == nil || !*created.RW ||
		created.MemoryMiB != 512 || len(created.SecretNames) != 1 {
		t.Fatalf("create body = %+v", created)
	}

	// 202 replay: the client polls the operation to completion.
	if _, err := client.StartSandbox(ctx, "dev"); err != nil {
		t.Fatal(err)
	}
	if operations != 2 {
		t.Fatalf("start polled %d times, want 2 (start + one poll)", operations)
	}

	if _, err := client.StopSandbox(ctx, "dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeleteSandbox(ctx, "dev"); err != nil {
		t.Fatal(err)
	}

	result, err := client.Exec(ctx, "dev", managerapi.ExecRequest{Argv: []string{"sh", "-c", "exit 3"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 3 || result.Output != "out:sh,-c,exit 3" || !result.Truncated {
		t.Fatalf("Exec = %+v", result)
	}

	var apiErr *Error
	err = client.do(ctx, http.MethodGet, "/v1/sandboxes/dev", nil, false, nil)
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound || apiErr.Message != "sandbox not found" {
		t.Fatalf("get missing sandbox = %v, want 404 Error", err)
	}
}

func TestExtractTarget(t *testing.T) {
	for _, test := range []struct {
		name       string
		argv       []string
		env        string
		wantTarget string
		wantRest   []string
		wantErr    string
	}{
		{name: "no flag no env", argv: []string{"dev"}, wantTarget: "", wantRest: []string{"dev"}},
		{name: "env only", argv: []string{"dev"}, env: "cloud", wantTarget: "cloud", wantRest: []string{"dev"}},
		{name: "flag wins over env", argv: []string{"dev", "-remote", "other"}, env: "cloud", wantTarget: "other", wantRest: []string{"dev"}},
		{name: "flag before name", argv: []string{"-remote", "cloud", "dev"}, wantTarget: "cloud", wantRest: []string{"dev"}},
		{name: "equals form", argv: []string{"dev", "-remote=cloud"}, wantTarget: "cloud", wantRest: []string{"dev"}},
		{name: "double-dash equals form", argv: []string{"--remote=cloud", "dev"}, wantTarget: "cloud", wantRest: []string{"dev"}},
		{name: "explicit local override", argv: []string{"-remote", ""}, env: "cloud", wantTarget: "", wantRest: []string{}},
		{name: "scan stops at separator", argv: []string{"dev", "--", "cmd", "-remote", "x"}, env: "cloud", wantTarget: "cloud", wantRest: []string{"dev", "--", "cmd", "-remote", "x"}},
		{name: "missing value", argv: []string{"dev", "-remote"}, wantErr: "requires a profile name"},
		{name: "duplicate", argv: []string{"-remote", "a", "-remote", "b"}, wantErr: "duplicate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, rest, err := ExtractTarget(test.argv, test.env)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("ExtractTarget = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if target != test.wantTarget || fmt.Sprint(rest) != fmt.Sprint(test.wantRest) {
				t.Fatalf("ExtractTarget = %q %v, want %q %v", target, rest, test.wantTarget, test.wantRest)
			}
		})
	}
}

func TestFlagPresent(t *testing.T) {
	if !FlagPresent([]string{"dev", "-remote", "cloud"}) {
		t.Error("missed plain flag")
	}
	if !FlagPresent([]string{"--remote=cloud"}) {
		t.Error("missed equals form")
	}
	if FlagPresent([]string{"dev", "--", "-remote", "cloud"}) {
		t.Error("flag after -- is command text")
	}
	if FlagPresent([]string{"dev"}) {
		t.Error("false positive")
	}
}
