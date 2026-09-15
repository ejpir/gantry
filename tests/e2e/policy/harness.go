package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const maxOutput = 1 << 20
const deniedExit = 23

type result struct {
	output string
	code   int
}
type harness struct {
	opts        options
	root, state string
	env         []string
	secrets     []string
	owned       []string
	checks      int
	fixtures    *fixtures
}

// commandBuffer keeps diagnostics bounded and is safe for os/exec's separate
// stdout/stderr copy goroutines. Truncation fails the check, never passes it.
type commandBuffer struct {
	mu        sync.Mutex
	buffer    bytes.Buffer // do not embed: io.Copy must not bypass Write via ReaderFrom
	truncated bool
}

func (b *commandBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func (b *commandBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Len()
}

func (b *commandBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := maxOutput - b.buffer.Len()
	if len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.buffer.Write(p)
	return n, nil
}

func newHarness(opts options) (*harness, error) {
	paths := []*string{&opts.gantry}
	if !opts.cliOnly {
		paths = append(paths, &opts.kernel, &opts.rootfs, &opts.image)
	}
	for _, p := range paths {
		if *p == "" {
			return nil, fmt.Errorf("gantry, kernel, rootfs and local image paths are required (gantry only with -cli-only)")
		}
		absolute, err := filepath.Abs(*p)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(absolute)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("not a regular file: %s", absolute)
		}
		*p = absolute
	}
	parent := opts.workDir
	if parent == "" && runtime.GOOS != "windows" {
		parent = "/tmp"
	}
	root, err := os.MkdirTemp(parent, "gpo-")
	if err != nil {
		return nil, err
	}
	physical, err := filepath.EvalSymlinks(root)
	if err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}
	root, err = filepath.Abs(physical)
	if err != nil {
		_ = os.RemoveAll(physical)
		return nil, err
	}
	h := &harness{opts: opts, root: root, state: filepath.Join(root, "state", "sandboxes")}
	// Fail early rather than attributing sockaddr_un truncation to policy.
	if runtime.GOOS != "windows" && len(filepath.Join(h.state, "pol-deny-mount", "listen-1026.sock")) >= 104 {
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("workspace too long for Unix sockets; choose a shorter -work-dir")
	}
	for i := 0; i < 2; i++ {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			_ = os.RemoveAll(root)
			return nil, err
		}
		h.secrets = append(h.secrets, "opa-e2e-"+hex.EncodeToString(raw[:]))
	}
	values := map[string]string{"GANTRY_HOME": h.state, "GANTRY_IMAGES": filepath.Join(root, "images"), "OPA_ALLOW": h.secrets[0], "OPA_DENY": h.secrets[1]}
	if opts.artifacts != "" {
		values["GANTRY_ARTIFACTS"] = opts.artifacts
	}
	h.env = environment(os.Environ(), values)
	return h, nil
}

func environment(base []string, values map[string]string) []string {
	var out []string
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		replaced := false
		for k := range values {
			if strings.EqualFold(key, k) {
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, entry)
		}
	}
	for key, value := range values {
		out = append(out, key+"="+value)
	}
	return out
}

func (h *harness) redact(value string) string {
	for _, secret := range h.secrets {
		value = strings.ReplaceAll(value, secret, "[E2E-CREDENTIAL]")
	}
	return value
}

func (h *harness) command(ctx context.Context, input string, args ...string) (result, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.opts.gantry, args...)
	cmd.Env = h.env
	cmd.Dir = h.root
	cmd.Stdin = strings.NewReader(input)
	cmd.WaitDelay = 3 * time.Second
	var output commandBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	r := result{output: output.String()}
	log, logErr := os.OpenFile(filepath.Join(h.root, "commands.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if logErr != nil {
		return r, logErr
	}
	_, logErr = fmt.Fprintf(log, "$ gantry %s\n%s\n", h.redact(strings.Join(args, " ")), h.redact(r.output))
	closeErr := log.Close()
	if logErr != nil {
		return r, logErr
	}
	if closeErr != nil {
		return r, closeErr
	}
	if ctx.Err() != nil {
		return r, fmt.Errorf("command %s: %w", args[0], ctx.Err())
	}
	if output.truncated {
		return r, fmt.Errorf("command %s exceeded output limit", args[0])
	}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return r, err
		}
		r.code = exit.ExitCode()
	}
	return r, nil
}

func (h *harness) expect(ctx context.Context, label string, code int, contains string, args ...string) (string, error) {
	r, err := h.command(ctx, "", args...)
	if err != nil {
		return "", fmt.Errorf("%s: %w", label, err)
	}
	if r.code != code || !strings.Contains(r.output, contains) {
		return "", fmt.Errorf("%s: exit=%d, want %d and %q; output: %s", label, r.code, code, contains, h.redact(r.output))
	}
	h.pass(label)
	return r.output, nil
}
func (h *harness) pass(label string) { h.checks++; fmt.Println("PASS:", label) }
func (h *harness) guest(ctx context.Context, label, script string, code int, contains string) (string, error) {
	return h.expect(ctx, label, code, contains, "exec", "pol-main", "--", "sh", "-c", script)
}
func (h *harness) startArgs(name string, extra ...string) []string {
	return append([]string{"start", name, "-kernel", h.opts.kernel, "-rootfs", h.opts.rootfs, "-image", h.opts.image, "-mem", "512", "-cpus", "1", "-process-isolation", "auto"}, extra...)
}
func (h *harness) start(ctx context.Context, name string, extra ...string) error {
	h.owned = append(h.owned, name)
	_, err := h.expect(ctx, "start "+name, 0, "", h.startArgs(name, extra...)...)
	return err
}
func (h *harness) startDenied(ctx context.Context, name, reason string, extra ...string) error {
	h.owned = append(h.owned, name)
	_, err := h.expect(ctx, "start refuses "+name, 1, reason, h.startArgs(name, extra...)...)
	return err
}
func (h *harness) cleanup() error {
	var failures []error
	cleanupContext, finish := context.WithTimeout(context.Background(), 2*time.Minute)
	defer finish()
	for i := len(h.owned) - 1; i >= 0; i-- {
		name := h.owned[i]
		if _, err := os.Stat(filepath.Join(h.state, name)); os.IsNotExist(err) {
			continue
		}
		// Stop only our names under the private GANTRY_HOME, even on failure.
		ctx, cancel := context.WithTimeout(cleanupContext, 30*time.Second)
		_, _ = h.command(ctx, "", "stop", name)
		cancel()
		ctx, cancel = context.WithTimeout(cleanupContext, 30*time.Second)
		r, err := h.command(ctx, "", "delete", name)
		cancel()
		// Failed preflight starts need not have created a directory.
		if _, statErr := os.Stat(filepath.Join(h.state, name)); !os.IsNotExist(statErr) && (err != nil || r.code != 0) {
			failures = append(failures, fmt.Errorf("cleanup %s failed", name))
		}
	}
	return errors.Join(failures...)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, data, mode)
}

// A missing guest utility is an infrastructure failure, not a passing deny.
const probePrerequisites = `command -v timeout >/dev/null || { echo OPA-MISSING-timeout; exit 42; }
if command -v curl >/dev/null; then :; elif command -v wget >/dev/null; then :; else echo OPA-MISSING-http-client; exit 42; fi
if command -v getent >/dev/null; then :; elif command -v nslookup >/dev/null; then :; else echo OPA-MISSING-dns-client; exit 42; fi
test -x /run/gantry/bin/credhelper || { echo OPA-MISSING-credhelper; exit 42; }
test -x /run/gantry/bin/gantry-guest || { echo OPA-MISSING-gantry-guest; exit 42; }
echo OPA-PROBES-READY`

func httpProbe(url string) string {
	return fmt.Sprintf(`unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
if command -v curl >/dev/null; then
  timeout 8 curl --noproxy '*' -fsS --connect-timeout 3 --max-time 5 '%s'
else
  timeout 8 wget -q -T 4 -O - '%s'
fi
status=$?
if [ "$status" -eq 0 ]; then exit 0; fi
if [ "$status" -eq 126 ] || [ "$status" -eq 127 ]; then exit 42; fi
echo OPA-NET-DENIED
exit 23`, url, url)
}
func dnsProbe(host string) string {
	return fmt.Sprintf(`if command -v nslookup >/dev/null; then
  timeout 8 nslookup -type=A '%s' 192.168.127.1
else
  timeout 8 getent ahostsv4 '%s'
fi
status=$?
if [ "$status" -eq 0 ]; then exit 0; fi
if [ "$status" -eq 126 ] || [ "$status" -eq 127 ]; then exit 42; fi
echo OPA-DNS-DENIED
exit 23`, host, host)
}

var _ io.Writer = (*commandBuffer)(nil)
