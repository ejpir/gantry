// oidc is a standalone, VM-free black-box OIDC login battery using a disposable
// loopback HTTPS IdP. It launches the actual Gantry CLI, not an auth mock.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/orgauth/testidp"
	"github.com/ejpir/gantry/internal/sandbox/config"
)

func main() {
	binary := flag.String("gantry", "", "Gantry executable to test (required)")
	timeout := flag.Duration("timeout", 2*time.Minute, "overall deadline")
	flag.Parse()
	if *binary == "" || *timeout <= 0 || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := run(ctx, *binary); err != nil {
		fmt.Fprintln(os.Stderr, "OIDC E2E:", err)
		os.Exit(1)
	}
}

type harness struct {
	binary, root, home, source string
	idp                        *testidp.Provider
	checks                     int
}

// cappedBuffer deliberately contains (not embeds) bytes.Buffer so io.Copy
// cannot bypass its bounds via a promoted ReaderFrom method.
type cappedBuffer struct {
	mu       sync.Mutex
	data     bytes.Buffer
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := (256 << 10) - b.data.Len()
	if len(p) > remaining {
		p = p[:remaining]
		b.overflow = true
	}
	_, _ = b.data.Write(p)
	return n, nil
}

func (b *cappedBuffer) result() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.String(), b.overflow
}

func run(ctx context.Context, binary string) error {
	binary, err := filepath.Abs(binary)
	if err != nil {
		return err
	}
	root, err := os.MkdirTemp("", "gantry-oidc-e2e-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(root) }()
	idp, err := testidp.New()
	if err != nil {
		return err
	}
	defer idp.Close()
	source, err := idp.WriteConfig(root)
	if err != nil {
		return err
	}
	h := &harness{binary: binary, root: root, home: filepath.Join(root, "sandboxes"), source: source, idp: idp}
	if err := h.battery(ctx); err != nil {
		return err
	}
	fmt.Printf("OIDC E2E: %d checks passed (local HTTPS IdP; no VM or external account).\n", h.checks)
	return nil
}

func (h *harness) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, h.binary, args...)
	// Preserve platform runtime variables, but never inherit Gantry configuration
	// or OAuth secrets. Commands use pipes, disabling interactive update checks.
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(name)
		if !strings.HasPrefix(upper, "GANTRY_") && !strings.Contains(upper, "OAUTH") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "GANTRY_HOME="+h.home, "GANTRY_IMAGES="+filepath.Join(h.root, "images"))
	cmd.Dir = h.root
	cmd.WaitDelay = time.Second
	return cmd
}

func (h *harness) checkOutput(stdout, stderr *cappedBuffer) (string, error) {
	out, outLarge := stdout.result()
	errText, errLarge := stderr.result()
	if outLarge || errLarge {
		return "", fmt.Errorf("CLI output exceeded bound")
	}
	for _, secret := range append(h.idp.Secrets(), "UPSTREAM-ERROR-CANARY") {
		if strings.Contains(out+errText, secret) {
			return "", fmt.Errorf("CLI leaked an OAuth credential or upstream error body")
		}
	}
	return out, nil
}

func (h *harness) cli(ctx context.Context, success bool, args ...string) (string, error) {
	cmd := h.command(ctx, args...)
	var stdout, stderr cappedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if !expectedExit(err, success) || ctx.Err() != nil {
		// Do not echo raw process output: negative cases deliberately carry
		// credential canaries and reflected upstream errors.
		return "", fmt.Errorf("check %d: unexpected CLI result for %s %s (want success=%v, process error=%v, deadline=%v)", h.checks+1, args[0], args[1], success, err, ctx.Err())
	}
	out, err := h.checkOutput(&stdout, &stderr)
	if err == nil {
		h.checks++
	}
	return out, err
}

func (h *harness) login(ctx context.Context, scenario testidp.Scenario, profile string, success bool) (string, error) {
	h.idp.Set(scenario)
	timeout := "10s"
	if scenario.Fault == "callback-state" || scenario.Fault == "callback-issuer" || scenario.Fault == "duplicate-state" {
		timeout = "2s"
	}
	args := []string{"org", "login", "-config", h.source, "-no-browser", "-timeout", timeout}
	if profile != "" {
		args = append(args, "-profile", profile)
	}
	cmd := h.command(ctx, args...)
	var stdout, stderr cappedBuffer
	cmd.Stdout = &stdout
	pipe, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	defer func() { _ = pipe.Close() }()
	browserDone := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(io.TeeReader(pipe, &stderr))
		scanner.Buffer(make([]byte, 4096), 64<<10)
		var visitErr error
		visited := false
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "https://") && !visited {
				visited = true
				visitErr = h.idp.Visit(line)
			}
		}
		if scanner.Err() != nil {
			visitErr = fmt.Errorf("CLI stderr read failed")
			_, _ = io.Copy(&stderr, pipe)
		}
		browserDone <- visitErr
	}()
	// Drain the pipe before Wait closes it. The overall context kills a stuck
	// CLI, while the synthetic browser has its own five-second deadline.
	visitErr := <-browserDone
	runErr := cmd.Wait()
	if visitErr != nil || !expectedExit(runErr, success) || ctx.Err() != nil {
		return "", fmt.Errorf("unexpected login result for %q (want success=%v)", scenario.Fault, success)
	}
	out, err := h.checkOutput(&stdout, &stderr)
	if err == nil && !success {
		text, _ := stderr.result()
		if !strings.Contains(text, expectedLoginError(scenario.Fault)) {
			return "", fmt.Errorf("login failure did not reach expected authorization gate: %s", scenario.Fault)
		}
	}
	if err == nil {
		h.checks++
	}
	return out, err
}

func expectedExit(err error, success bool) bool {
	if success {
		return err == nil
	}
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == 1
}

func expectedLoginError(fault string) string {
	switch fault {
	case "discovery-issuer", "oversized-discovery":
		return "OIDC discovery failed"
	case "http-endpoint":
		return "endpoints must use HTTPS"
	case "callback-state", "callback-issuer", "duplicate-state":
		return "canceled or timed out"
	case "denied":
		return "identity provider denied"
	case "pkce", "token-redirect":
		return "OIDC code exchange failed"
	case "nonce", "future-iat", "no-subject":
		return "OIDC ID token binding or lifetime"
	case "at-hash":
		return "OIDC access-token binding"
	case "no-id-token":
		return "requires a bounded ID token"
	case "azp":
		return "OIDC authorized party"
	case "multi-aud":
		return "multiple audiences requires azp"
	case "no-groups":
		return "supported membership claim"
	case "":
		return "profile" // unmatched, unauthorized selection, or ambiguous membership
	default:
		return "OIDC ID token verification failed"
	}
}

func (h *harness) battery(ctx context.Context) error {
	if _, err := h.cli(ctx, false, "org", "status", testidp.Organization); err != nil {
		return err
	}
	if _, err := h.login(ctx, testidp.Scenario{Fault: "signature"}, "", false); err != nil {
		return err
	}
	if _, err := os.Lstat(h.home + "-orgs"); !os.IsNotExist(err) {
		return fmt.Errorf("rejected first login created a receipt store")
	}
	out, err := h.login(ctx, testidp.Scenario{}, "", true)
	if err != nil {
		return err
	}
	var receipt struct {
		Organization string    `json:"organization"`
		Subject      string    `json:"subject"`
		Profile      string    `json:"profile"`
		Revision     string    `json:"revision"`
		ExpiresAt    time.Time `json:"expires_at"`
	}
	if json.Unmarshal([]byte(out), &receipt) != nil || receipt.Organization != testidp.Organization || receipt.Subject != "synthetic-user" || receipt.Profile != "developer" || receipt.Revision != "oidc-e2e-1" {
		return fmt.Errorf("login provenance does not match verified identity/policy")
	}
	baseline, err := h.sessionBytes()
	if err != nil {
		return err
	}
	// Real subprocess restart: status loads only the token-free saved receipt.
	if _, err := h.cli(ctx, true, "org", "status", testidp.Organization); err != nil {
		return err
	}
	for _, fault := range []string{
		"signature", "issuer", "audience", "nonce", "expired", "future-iat", "future-nbf", "azp", "multi-aud", "no-subject", "no-groups", "at-hash", "no-id-token", "pkce", "denied",
		"callback-state", "callback-issuer", "duplicate-state", "discovery-issuer", "http-endpoint", "oversized-discovery", "token-redirect",
	} {
		if _, err := h.login(ctx, testidp.Scenario{Fault: fault}, "", false); err != nil {
			return err
		}
		after, err := h.sessionBytes()
		if err != nil || !bytes.Equal(after, baseline) {
			return fmt.Errorf("failed login replaced previous valid receipt")
		}
	}
	for _, tc := range []struct {
		groups  []string
		profile string
	}{
		{[]string{}, ""}, {[]string{"other-org"}, ""}, {[]string{"example-developers"}, "admin"},
		{[]string{"example-developers", "example-admins"}, ""},
	} {
		if _, err := h.login(ctx, testidp.Scenario{Groups: tc.groups}, tc.profile, false); err != nil {
			return err
		}
	}
	if _, err := h.login(ctx, testidp.Scenario{Groups: []string{"example-developers", "example-admins"}}, "developer", true); err != nil {
		return err
	}
	// Apply to a minimal stopped sandbox fixture: no hypervisor or daemon.
	name := "oidc-stopped"
	dir := filepath.Join(h.home, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(config.RunConfig{MemMB: 512, VCPUs: 1, ProcessIsolation: "required"})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), data, 0o600); err != nil {
		return err
	}
	if _, err := h.cli(ctx, true, "org", "apply", testidp.Organization, name); err != nil {
		return err
	}
	out, err = h.cli(ctx, true, "policy", "show", name)
	if err != nil || !strings.Contains(out, `"profile":"developer"`) || !strings.Contains(out, `"revision":"oidc-e2e-1"`) {
		return fmt.Errorf("applied policy snapshot does not match login")
	}
	// Source files are not reopened by status/apply: the receipt pins the bundle.
	for _, file := range []string{"bundle.tar.gz", "policy-public.pem"} {
		if err := os.WriteFile(filepath.Join(h.root, file), []byte("corrupted after login"), 0o600); err != nil {
			return err
		}
	}
	if _, err := h.cli(ctx, true, "org", "apply", testidp.Organization, name); err != nil {
		return err
	}
	if _, err := h.cli(ctx, true, "org", "logout", testidp.Organization); err != nil {
		return err
	}
	if _, err := h.cli(ctx, false, "org", "status", testidp.Organization); err != nil {
		return err
	}
	if _, err := h.cli(ctx, false, "org", "apply", testidp.Organization, name); err != nil {
		return err
	}
	if _, err := h.cli(ctx, true, "policy", "show", name); err != nil {
		return err // logout must not silently revoke pinned sandbox policy
	}
	// Restore fresh fixture policy and use a genuinely short-lived signed ID token.
	if _, err := h.idp.WriteConfig(h.root); err != nil {
		return err
	}
	out, err = h.login(ctx, testidp.Scenario{Fault: "short-lived"}, "", true)
	if err != nil || json.Unmarshal([]byte(out), &receipt) != nil {
		return fmt.Errorf("short-lived login failed")
	}
	timer := time.NewTimer(time.Until(receipt.ExpiresAt) + 100*time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	if _, err := h.cli(ctx, false, "org", "status", testidp.Organization); err != nil {
		return err
	}
	if _, err := h.cli(ctx, false, "org", "apply", testidp.Organization, name); err != nil {
		return err
	}
	if h.idp.Count("/leak") != 0 {
		return fmt.Errorf("token exchange followed a redirect")
	}
	for _, endpoint := range []string{"/.well-known/openid-configuration", "/authorize", "/token", "/keys"} {
		if h.idp.Count(endpoint) == 0 {
			return fmt.Errorf("OIDC endpoint not exercised: %s", endpoint)
		}
	}
	return h.checkDisk()
}

func (h *harness) sessionBytes() ([]byte, error) {
	files, err := filepath.Glob(filepath.Join(h.home+"-orgs", "*.json"))
	if err != nil || len(files) != 1 {
		return nil, fmt.Errorf("expected one organization receipt")
	}
	return os.ReadFile(files[0])
}

func (h *harness) checkDisk() error {
	return filepath.WalkDir(h.root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, secret := range append(h.idp.Secrets(), "PRIVATE KEY", "UPSTREAM-ERROR-CANARY") {
			if bytes.Contains(data, []byte(secret)) {
				return fmt.Errorf("credential material persisted by login")
			}
		}
		return nil
	})
}
