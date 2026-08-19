package controlcmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// writeSandboxConfig persists a minimal valid configuration for name.
func writeSandboxConfig(t *testing.T, name string) string {
	t.Helper()
	dir := layout.Dir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.RunConfig{MemMB: 512, VCPUs: 1, ProcessIsolation: "required"}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// fakeLiveSandbox makes name look running: a live pid recorded in vmm.pid,
// the daemon lifetime lock held, and a control server that captures one
// request and replies with response.
func fakeLiveSandbox(t *testing.T, name, response string) <-chan controlproto.Request {
	t.Helper()
	dir := writeSandboxConfig(t, name)
	if err := os.WriteFile(filepath.Join(dir, "vmm.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := layout.HoldLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })

	listener, err := net.Listen("unix", filepath.Join(dir, "ctl.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	captured := make(chan controlproto.Request, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		line, err := controlproto.ReadBoundedLine(bufio.NewReader(conn), controlproto.MaxResponseBytes)
		if err != nil {
			return
		}
		var req controlproto.Request
		if err := json.Unmarshal(line, &req); err != nil {
			return
		}
		captured <- req
		_, _ = fmt.Fprintln(conn, response)
	}()
	return captured
}

// TestSetResourcesLivePassesIsolationThroughUnchanged is the regression
// guard for the live/stopped asymmetry: an omitted mode must reach the
// daemon as "" (preserve the stored value), not be pre-normalized to
// "auto" here while the stopped path preserves.
func TestSetResourcesLivePassesIsolationThroughUnchanged(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	captured := fakeLiveSandbox(t, "rsrc", `{"ok":true}`)
	if err := SetResources("rsrc", 2048, 2, ""); err != nil {
		t.Fatal(err)
	}
	req := <-captured
	if req.Resources == nil {
		t.Fatal("resources request missing payload")
	}
	if req.Resources.ProcessIsolation != "" {
		t.Fatalf("process isolation = %q, want empty (preserve)", req.Resources.ProcessIsolation)
	}
	if req.Resources.MemMB != 2048 || req.Resources.VCPUs != 2 {
		t.Fatalf("resources = %+v", req.Resources)
	}
}

// TestSetNetworkPolicyStoppedSandboxWritesStore covers the offline path:
// no daemon anywhere, the policy is validated and persisted for next boot.
func TestSetNetworkPolicyStoppedSandboxWritesStore(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	writeSandboxConfig(t, "stopped")
	entry, err := SetNetworkPolicy("stopped", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if entry.State != "saved" {
		t.Fatalf("state = %q, want saved", entry.State)
	}
	cfg, err := config.ReadSandboxConfig(layout.Dir("stopped"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NetPol != "" || cfg.AllowLN {
		t.Fatalf("persisted policy = %q allowLocal=%v, want cleared default", cfg.NetPol, cfg.AllowLN)
	}
}

// TestSetNetworkPolicyWhileLaunchLockHeld: a launcher holding the launch
// lock means a daemon may be mid-boot reading sandbox.json. The stopped
// path must refuse to write instead of silently losing the update.
func TestSetNetworkPolicyWhileLaunchLockHeld(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	writeSandboxConfig(t, "booting")
	lock, err := layout.HoldLaunchLock("booting")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	_, err = SetNetworkPolicy("booting", "", false)
	if err == nil || !strings.Contains(err.Error(), "launching") {
		t.Fatalf("SetNetworkPolicy = %v, want a launching conflict", err)
	}
}
