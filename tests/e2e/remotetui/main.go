// remotetui drives the real Gantry TUI in a POSIX PTY against disposable HTTPS
// manager/catalog/IdP fixtures. VM boot is intentionally replaced by the manager
// fixture; this battery validates onboarding, transport, custody and routing.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/orgauth"
	"github.com/ejpir/gantry/internal/orgauth/testidp"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/remoteprofile"
)

type fixtureState struct {
	Health     int                               `json:"health"`
	Rejected   int                               `json:"rejected"`
	Pulls      int                               `json:"pulls"`
	Watches    int                               `json:"watches"`
	Creates    []managerapi.CreateSandboxRequest `json:"creates"`
	Unexpected []string                          `json:"unexpected"`
}

type managerFixture struct {
	mu          sync.Mutex
	state       fixtureState
	path, token string
}

func (m *managerFixture) serve(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	if r.Header.Get("Authorization") != "Bearer "+m.token {
		m.state.Rejected++
		m.save()
		m.mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(managerapi.ErrorResponse{Error: "access denied"})
		return
	}
	if r.URL.Path == "/v1/events" && r.Method == http.MethodGet {
		m.state.Watches++
		m.save()
		m.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, ": subscribed\n\n")
		w.(http.Flusher).Flush()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-tick.C:
				_, _ = fmt.Fprint(w, ": heartbeat\n\n")
				w.(http.Flusher).Flush()
			}
		}
	}
	defer m.mu.Unlock()
	defer m.save()
	w.Header().Set("Content-Type", "application/json")
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/health":
		m.state.Health++
		_ = json.NewEncoder(w).Encode(managerapi.Health{OK: true, Version: "remote-tui-e2e"})
	case "GET /v1/images":
		images := []managerapi.Image{}
		if m.state.Pulls != 0 {
			images = append(images, managerapi.Image{Ref: "registry-1.docker.io/library/alpine:latest"})
		}
		_ = json.NewEncoder(w).Encode(managerapi.ImageList{Images: images})
	case "POST /v1/images/pull":
		var req managerapi.ImagePullRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Ref != "alpine" || r.Header.Get("Idempotency-Key") == "" {
			http.Error(w, "bad pull", http.StatusBadRequest)
			return
		}
		m.state.Pulls++
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "e2e-pull", Kind: "image.pull", State: "running", Progress: "fixture pull"})
	case "GET /v1/operations/e2e-pull":
		_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "e2e-pull", Kind: "image.pull", State: "succeeded"})
	case "GET /v1/sandboxes":
		rows := []managerapi.Sandbox{}
		for _, req := range m.state.Creates {
			rows = append(rows, managerapi.Sandbox{Name: req.Name, Image: req.Image, State: "running"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sandboxes": rows})
	case "POST /v1/sandboxes":
		var req managerapi.CreateSandboxRequest
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req) != nil || req.Name == "" || req.Kernel != "" || r.Header.Get("Idempotency-Key") == "" {
			http.Error(w, "bad create", http.StatusBadRequest)
			return
		}
		if req.OrganizationPolicy != nil {
			if _, err := policy.New(req.OrganizationPolicy, nil); err != nil {
				http.Error(w, "invalid signed policy", http.StatusBadRequest)
				return
			}
		}
		m.state.Creates = append(m.state.Creates, req)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "e2e-create-" + req.Name, Kind: "create", State: "succeeded"})
	default:
		m.state.Unexpected = append(m.state.Unexpected, r.Method+" "+r.URL.Path)
		http.Error(w, "unexpected fixture request", http.StatusNotFound)
	}
}

func (m *managerFixture) save() {
	raw, err := json.Marshal(m.state)
	if err == nil {
		_ = atomicfile.WriteFile(m.path, raw, 0o600)
	}
}

func main() {
	gantry := flag.String("gantry", "", "path to Gantry development binary")
	python := flag.String("python", "python3", "Python 3 executable (standard library only)")
	script := flag.String("script", "tests/e2e/remotetui/tui.py", "PTY driver path")
	flag.Parse()
	if *gantry == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./tests/e2e/remotetui -gantry /path/to/gantry")
		os.Exit(2)
	}
	if runtime.GOOS == "windows" {
		fmt.Fprintln(os.Stderr, "remote TUI E2E requires a POSIX PTY (Linux or macOS)")
		os.Exit(2)
	}
	if err := run(*gantry, *python, *script); err != nil {
		fmt.Fprintln(os.Stderr, "remote TUI E2E:", err)
		os.Exit(1)
	}
}

func run(gantry, python, script string) error {
	gantry, err := filepath.Abs(gantry)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "gantry-remote-tui-e2e-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	token := hex.EncodeToString(secret)
	manager := &managerFixture{path: filepath.Join(dir, "manager-state.json"), token: token}
	manager.save()
	server := httptest.NewTLSServer(http.HandlerFunc(manager.serve))
	defer server.Close()
	caPath := filepath.Join(dir, "manager-ca.pem")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		return err
	}
	idp, err := testidp.New()
	if err != nil {
		return err
	}
	defer idp.Close()
	configPath, err := idp.WriteConfig(dir)
	if err != nil {
		return err
	}
	profile := remoteprofile.Profile{Name: "org-team", URL: server.URL, CACert: string(ca)}
	var catalog *httptest.Server
	catalog = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !idp.ValidAccessToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), catalog.URL, "gantry.catalog.read") {
			http.Error(w, "invalid catalog credential", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(orgauth.RemoteCatalog{Version: 1, Organization: testidp.Organization, Subject: "synthetic-user", ExpiresAt: time.Now().Add(time.Minute), Remotes: []remoteprofile.Profile{profile}})
	}))
	defer catalog.Close()
	idp.Set(testidp.Scenario{Resource: catalog.URL, Scope: "gantry.catalog.read"})
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var config orgauth.Config
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}
	config.RemoteCatalog = &orgauth.CatalogConfig{URL: catalog.URL, Resource: catalog.URL, Scope: "gantry.catalog.read", CAFile: "catalog-ca.pem"}
	data, err = json.Marshal(config)
	if err != nil {
		return err
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "catalog-ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: catalog.Certificate().Raw}), 0o600); err != nil {
		return err
	}
	browserFile := filepath.Join(dir, "browser-url")
	shimDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(shimDir, 0o700); err != nil {
		return err
	}
	// Replace only the OS browser launcher in the subprocess PATH. Gantry's
	// production OIDC verifier and loopback callback remain unmodified.
	for _, name := range []string{"xdg-open", "open"} {
		if err := os.WriteFile(filepath.Join(shimDir, name), []byte("#!/bin/sh\nprintf '%s' \"$1\" > \"$GANTRY_E2E_BROWSER_URL\"\n"), 0o700); err != nil {
			return err
		}
	}
	browserCtx, stopBrowser := context.WithCancel(ctx)
	browserDone := make(chan struct{})
	go func() {
		defer close(browserDone)
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		last := ""
		for {
			select {
			case <-browserCtx.Done():
				return
			case <-tick.C:
				raw, err := os.ReadFile(browserFile)
				if err == nil && len(raw) > 0 && string(raw) != last {
					if idp.Visit(string(raw)) == nil {
						last = string(raw)
					}
				}
			}
		}
	}()
	defer func() { stopBrowser(); <-browserDone }()
	metadata := map[string]string{"gantry": gantry, "root": dir, "manager": server.URL, "token": token, "ca": caPath, "config": configPath, "state": manager.path, "browser": browserFile, "shim": shimDir}
	metadataPath := filepath.Join(dir, "fixture.json")
	data, err = json.Marshal(metadata)
	if err != nil {
		return err
	}
	if err := os.WriteFile(metadataPath, data, 0o600); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, python, script, metadataPath)
	output, err := command.CombinedOutput()
	clean := strings.ReplaceAll(string(output), token, "[manager token redacted]")
	for _, credential := range idp.Secrets() {
		clean = strings.ReplaceAll(clean, credential, "[OIDC credential redacted]")
	}
	fmt.Print(clean)
	if err != nil {
		return fmt.Errorf("PTY driver: %w", err)
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.state.Unexpected) != 0 || len(manager.state.Creates) != 2 || manager.state.Pulls != 1 || manager.state.Rejected != 1 {
		return fmt.Errorf("unexpected request routing (creates=%d pulls=%d refusals=%d)", len(manager.state.Creates), manager.state.Pulls, manager.state.Rejected)
	}
	if manager.state.Creates[0].OrganizationPolicy != nil || manager.state.Creates[1].OrganizationPolicy == nil {
		return fmt.Errorf("standalone/organization policy routing was lost")
	}
	for _, home := range []string{"standalone", "organization"} {
		matches, _ := filepath.Glob(filepath.Join(dir, home, "sandboxes", "*"))
		if len(matches) != 0 {
			return fmt.Errorf("remote flow created local sandbox state")
		}
	}
	for _, credential := range idp.Secrets() {
		matches, _ := filepath.Glob(filepath.Join(dir, "organization", "sandboxes-orgs", "*.json"))
		for _, path := range matches {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(raw), credential) {
				return fmt.Errorf("OIDC credential persisted in receipt")
			}
		}
	}
	fmt.Println("PASS real-binary TUI onboarding (standalone + organization; no VM boot)")
	return nil
}
