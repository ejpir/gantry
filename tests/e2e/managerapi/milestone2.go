package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/sandbox/config"
)

// m2Client deliberately has a different state tree and cwd from the manager.
// Same-named local fixtures detect accidental local fallback rather than merely
// observing a successful request against a loopback server.
type m2Client struct {
	gantry, dir, root, managerRoot, logPath string
	env                                     []string
	api                                     *apiClient
	token                                   string
}

func newM2Client(ctx context.Context, work, gantry, managerRoot, logPath string, env []string, transport tlsHarness, api *apiClient) (*m2Client, error) {
	dir := filepath.Join(work, "client")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	m := &m2Client{gantry: gantry, dir: dir, root: filepath.Join(dir, "sandboxes"), managerRoot: managerRoot, logPath: logPath, api: api, token: transport.token}
	m.env = environmentFrom(env, map[string]string{"GANTRY_HOME": m.root, "GANTRY_REMOTE": "must-not-be-used"})
	ca := filepath.Join(work, "serve", "ca.crt")
	pin, err := tlsFingerprintFromLog(logPath)
	if err != nil {
		return nil, err
	}
	// Probe failure must neither save a profile nor fall through locally.
	_, _, err = m.cli(ctx, 1, "remote", "add", "bad-pin", "https://"+transport.address, "--token-file", transport.tokenPath, "--ca", ca, "--fingerprint", "sha256:"+strings.Repeat("0", 64))
	if err != nil {
		return nil, err
	}
	_, _, err = m.cli(ctx, 0, "remote", "add", "m2", "https://"+transport.address, "--token-file", transport.tokenPath, "--ca", ca, "--fingerprint", "sha256:"+pin)
	return m, err
}

func (m *m2Client) cli(ctx context.Context, want int, args ...string) (string, string, error) {
	return m.command(ctx, m.gantry, nil, want, args...)
}

func (m *m2Client) command(ctx context.Context, program string, stdin io.Reader, want int, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Dir = m.dir
	cmd.Env = m.env
	cmd.Stdin = stdin
	cmd.WaitDelay = 3 * time.Second
	var out, errs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errs
	err := cmd.Run()
	if m.token != "" && (strings.Contains(out.String(), m.token) || strings.Contains(errs.String(), m.token)) {
		return "", "", fmt.Errorf("%s leaked the manager token in command output", filepath.Base(program))
	}
	if ctx.Err() != nil {
		return out.String(), errs.String(), fmt.Errorf("%s %s: %w", filepath.Base(program), strings.Join(args, " "), ctx.Err())
	}
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			return "", "", err
		}
	}
	if code != want {
		return out.String(), errs.String(), fmt.Errorf("%s %s exit=%d, want %d: %s", filepath.Base(program), strings.Join(args, " "), code, want, errs.String())
	}
	return out.String(), errs.String(), nil
}

func writeM2Fixture(root, name string) (string, error) {
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := config.WriteSandboxConfig(dir, config.RunConfig{MemMB: 512, VCPUs: 1, Runtime: "crun", SSH: true, ProcessIsolation: "required"}); err != nil {
		return "", err
	}
	return filepath.Join(dir, "sandbox.json"), nil
}

func (m *m2Client) stoppedAndRunChecks(ctx context.Context) error {
	name := "m2-configure"
	remotePath, err := writeM2Fixture(m.managerRoot, name)
	if err != nil {
		return err
	}
	localPath, err := writeM2Fixture(m.root, name)
	if err != nil {
		return err
	}
	localBefore, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	defer func() { _, _, _, _ = m.api.do(ctx, http.MethodDelete, "/v1/sandboxes/"+name, nil, nil) }()
	out, _, err := m.cli(ctx, 0, "configure", name, "-remote", "m2", "-ssh=false", "-mem", "768", "-cpus", "2", "-key", "m2-stopped")
	if err != nil {
		return err
	}
	if strings.Contains(out, "restart required") || !strings.Contains(out, `remote "m2"`) {
		return fmt.Errorf("stopped result=%q", out)
	}
	cfg, err := config.ReadSandboxConfig(filepath.Dir(remotePath))
	if err != nil {
		return err
	}
	if cfg.SSH || cfg.MemMB != 768 || cfg.VCPUs != 2 || cfg.ProcessIsolation != "required" {
		return fmt.Errorf("partial configure did not preserve false/omission")
	}
	// API retries use exactly the bytes encoded by the canonical client type.
	ssh, mem, cpus := false, uint(768), 2
	body, err := json.Marshal(managerapi.ConfigureSandboxRequest{SSH: &ssh, MemoryMiB: &mem, CPUs: &cpus})
	if err != nil {
		return err
	}
	status, raw, _, err := m.api.do(ctx, http.MethodPatch, "/v1/sandboxes/"+name, body, map[string]string{"Idempotency-Key": "m2-stopped"})
	if err != nil {
		return err
	}
	if err := expectStatus(status, raw, http.StatusOK); err != nil {
		return err
	}
	var op managerapi.Operation
	if err := json.Unmarshal(raw, &op); err != nil {
		return err
	}
	if op.Configure == nil || op.Configure.RestartRequired {
		return fmt.Errorf("configure replay lost result")
	}
	lookupStatus, lookup, _, err := m.api.do(ctx, http.MethodGet, "/v1/operations/"+op.ID, nil, nil)
	if err != nil {
		return err
	}
	if lookupStatus != http.StatusOK || !bytes.Equal(raw, lookup) {
		return fmt.Errorf("configure operation lookup differs")
	}
	status, raw, _, err = m.api.do(ctx, http.MethodPatch, "/v1/sandboxes/"+name, []byte(`{"ssh":true}`), map[string]string{"Idempotency-Key": "m2-stopped"})
	if err != nil {
		return err
	}
	if err := expectStatus(status, raw, http.StatusConflict); err != nil {
		return err
	}
	for _, bad := range []string{`{}`, `{"memoryMiB":0}`, `{"cpus":-1}`, `{"ssh":false,"unknown":true}`} {
		status, raw, _, err = m.api.do(ctx, http.MethodPatch, "/v1/sandboxes/"+name, []byte(bad), nil)
		if err != nil {
			return err
		}
		if err := expectStatus(status, raw, http.StatusBadRequest); err != nil {
			return err
		}
	}
	if _, _, err = m.cli(ctx, 1, "configure", name, "-remote", "unknown", "-ssh=false"); err != nil {
		return err
	}
	// Authentication precedes body parsing even on the new mutation routes.
	for _, route := range []struct{ method, path string }{{http.MethodPatch, "/v1/sandboxes/" + name}, {http.MethodPost, "/v1/run"}} {
		status, raw, _, err = m.api.do(ctx, route.method, route.path, []byte("not JSON"), bearer("wrong-wrong-wrong-wrong"))
		if err != nil {
			return err
		}
		if err := expectStatus(status, raw, http.StatusForbidden); err != nil {
			return err
		}
	}
	// This kernel exists only in the client's cwd. A local fallback would
	// open it and fail later; the remote helper must fail opening the kernel.
	if err := os.WriteFile(filepath.Join(m.dir, "client-only-kernel"), []byte("client kernel canary"), 0o600); err != nil {
		return err
	}
	runArgs := []string{"run", "-remote", "m2", "-kernel", "client-only-kernel", "-rootfs", "missing-root", "-net-vfkit=false", "-vsocklisten=", "-timeout", "5", "-key", "m2-raw-missing"}
	console, _, err := m.cli(ctx, 1, runArgs...)
	if err != nil {
		return err
	}
	if !strings.Contains(console, "kernel") || !strings.Contains(console, "client-only-kernel") {
		return fmt.Errorf("raw run did not execute the manager's launcher: %q", console)
	}
	replay, _, err := m.cli(ctx, 1, runArgs...)
	if err != nil {
		return err
	}
	if replay != console {
		return fmt.Errorf("raw run replay changed console result")
	}
	if _, _, err = m.cli(ctx, 2, "run", "-remote", "m2", "-kernel", "missing"); err != nil {
		return err
	}
	if _, _, err = m.cli(ctx, 1, "run", "-remote", "unknown", "-kernel", "client-only-kernel", "-rootfs", "missing-root"); err != nil {
		return err
	}
	// Explicit local overrides GANTRY_REMOTE without changing either fixture.
	if _, _, err = m.cli(ctx, 0, "ls", "-remote="); err != nil {
		return err
	}
	localAfter, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(localBefore, localAfter) {
		return fmt.Errorf("remote request mutated same-named local sandbox")
	}
	if err := os.RemoveAll(filepath.Dir(localPath)); err != nil {
		return err
	}
	return m.audit(ctx, []string{"method=PATCH path=/v1/sandboxes/" + name + " status=200", "method=POST path=/v1/run status=200"})
}

func (m *m2Client) audit(_ context.Context, entries []string) error {
	data, err := os.ReadFile(m.logPath)
	if err != nil {
		return err
	}
	if bytes.Contains(data, []byte(m.token)) {
		return fmt.Errorf("audit contains raw bearer token")
	}
	for _, entry := range entries {
		found := false
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, entry) && strings.Contains(line, "remote=127.0.0.1:") && strings.Contains(line, "tokenfp="+e2eTokenFingerprint(m.token)) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing authenticated audit entry %q", entry)
		}
	}
	return nil
}

func m2LifecycleStartArgs(name string, opts options) []string {
	// This fixture enables SSH live. A writable root lets the daemon deliver
	// and verify guest tools via the share hub; -rw=false forces the bulk
	// exec-channel fallback and couples configure coverage to that transfer.
	args := []string{"start", name, "-remote", "m2", "-image", opts.image, "-rw=true", "-ssh=false", "-net=false", "-oauth-bridge=false", "-mem", "512", "-cpus", "1"}
	if opts.kernel != "" {
		args = append(args, "-kernel", opts.kernel)
	}
	if opts.rootfs != "" {
		args = append(args, "-rootfs", opts.rootfs)
	}
	return args
}

func (m *m2Client) lifecycleChecks(ctx context.Context, opts options) (runErr error) {
	const name = "m2-lifecycle"
	defer func() { cleanupSandbox(ctx, m.api, m.managerRoot, name, runErr != nil) }()
	if _, _, err := m.cli(ctx, 0, m2LifecycleStartArgs(name, opts)...); err != nil {
		return err
	}
	out, _, err := m.cli(ctx, 7, "exec", name, "-remote", "m2", "--", "/bin/sh", "-c", "printf remote-lifecycle; exit 7")
	if err != nil {
		return err
	}
	if !strings.Contains(out, "remote-lifecycle") {
		return fmt.Errorf("captured exec lost output")
	}
	out, _, err = m.cli(ctx, 0, "configure", name, "-remote", "m2", "-ssh=true", "-mem", "768", "-key", "m2-live")
	if err != nil {
		return err
	}
	if !strings.Contains(out, "restart required") {
		return fmt.Errorf("live resource change did not report restart")
	}
	status, raw, _, err := m.api.do(ctx, http.MethodGet, "/v1/sandboxes/"+name, nil, nil)
	if err != nil {
		return err
	}
	if err := expectStatus(status, raw, http.StatusOK); err != nil {
		return err
	}
	var state managerapi.Sandbox
	if err := json.Unmarshal(raw, &state); err != nil {
		return err
	}
	if !state.Writable || !state.RestartRequired || state.Active == nil || state.Active.MemoryMiB != 512 || state.Desired.MemoryMiB != 768 {
		return fmt.Errorf("live configure did not preserve active resources: %s", raw)
	}
	if err := m.sshChecks(ctx, name); err != nil {
		return err
	}
	if _, _, err = m.cli(ctx, 0, "stop", name, "-remote", "m2"); err != nil {
		return err
	}
	if _, _, err = m.cli(ctx, 0, "configure", name, "-remote", "m2", "-ssh=false", "-devcontainers=false", "-mem", "640"); err != nil {
		return err
	}
	// Default dispatch is tested separately from explicit-flag routing.
	oldEnv := m.env
	m.env = environmentFrom(m.env, map[string]string{"GANTRY_REMOTE": "m2"})
	_, _, err = m.cli(ctx, 0, "resume", name)
	m.env = oldEnv
	if err != nil {
		return err
	}
	if _, _, err = m.cli(ctx, 0, "exec", name, "-remote", "m2", "--", "/bin/true"); err != nil {
		return err
	}
	status, raw, _, err = m.api.do(ctx, http.MethodGet, "/v1/sandboxes/"+name, nil, nil)
	if err != nil {
		return err
	}
	if err := expectStatus(status, raw, http.StatusOK); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return err
	}
	if state.Active == nil || state.Active.MemoryMiB != 640 || state.RestartRequired {
		return fmt.Errorf("resume did not apply desired resources: %s", raw)
	}
	if err := step("SSH remains disabled after resume", func() error { return m.sshDisabledCheck(ctx, name) }); err != nil {
		return err
	}
	cfg, err := config.ReadSandboxConfig(filepath.Join(m.managerRoot, name))
	if err != nil {
		return err
	}
	if _, _, err = m.cli(ctx, 0, "delete", name, "-remote", "m2"); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(m.root, name)); !os.IsNotExist(err) {
		return fmt.Errorf("remote lifecycle created local state")
	}
	// Real low-level run is independent of named sandbox creation. It boots
	// the same verified host assets, then is killed/reaped at its deadline.
	_, diagnostic, err := m.cli(ctx, 124, "run", "-remote", "m2", "-kernel", cfg.Kernel, "-rootfs", cfg.Rootfs, "-timeout", "3", "-max-output", "1024", "-key", "m2-real-run")
	if err != nil {
		return err
	}
	if !strings.Contains(diagnostic, "deadline reached") {
		return fmt.Errorf("raw VM deadline was not reported")
	}
	return m.audit(ctx, []string{
		"method=PATCH path=/v1/sandboxes/" + name + " status=200", "method=POST path=/v1/run status=200",
		"method=POST path=/v1/sandboxes/" + name + "/ssh status=101",
		"method=POST path=/v1/sandboxes/" + name + "/ssh status=409",
	})
}
