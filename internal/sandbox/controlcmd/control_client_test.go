package controlcmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// useShortGantryHome points GANTRY_HOME at a short directory. ctl.sock lives
// under the sandbox directory, and AF_UNIX addresses are limited to ~104
// bytes on macOS and ~108 on Windows; t.TempDir() paths already exceed both
// (bind fails with EINVAL).
func useShortGantryHome(t *testing.T) {
	t.Helper()
	base := "/tmp"
	if runtime.GOOS == "windows" {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "gt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("GANTRY_HOME", dir)
}

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
	useShortGantryHome(t)
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

func TestConfigureLiveSendsOnlyRequestedSettings(t *testing.T) {
	useShortGantryHome(t)
	captured := fakeLiveSandbox(t, "configure-live", `{"ok":true,"restart_required":true}`)
	ssh, devContainers := true, true
	memMB := uint(4096)
	restart, err := Configure("configure-live", controlproto.ConfigureRequest{
		SSH: &ssh, DevContainers: &devContainers, MemMB: &memMB,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !restart {
		t.Fatal("restart requirement was not returned")
	}
	req := <-captured
	if req.Op != "sandbox.configure" || req.Configure == nil || req.Configure.SSH == nil || !*req.Configure.SSH ||
		req.Configure.DevContainers == nil || !*req.Configure.DevContainers || req.Configure.MemMB == nil || *req.Configure.MemMB != 4096 {
		t.Fatalf("configure request = %#v", req)
	}
	if req.Configure.VCPUs != nil || req.Configure.ProcessIsolation != nil {
		t.Fatalf("unset configure fields were sent: %+v", req.Configure)
	}
}

func TestConfigureStoppedPersistsFeaturesAndResources(t *testing.T) {
	useShortGantryHome(t)
	dir := writeSandboxConfig(t, "configure-stopped")
	store, err := config.LoadConfigStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Mutate(func(cfg *config.RunConfig) error {
		cfg.RW, cfg.RWLayer, cfg.Runtime = true, filepath.Join(dir, "rw.ext4"), "crun"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ssh, devContainers := true, true
	memMB, vcpus := uint(4096), min(4, config.MaxSandboxVCPUs())
	if restart, err := Configure("configure-stopped", controlproto.ConfigureRequest{
		SSH: &ssh, DevContainers: &devContainers, MemMB: &memMB, VCPUs: &vcpus,
	}); err != nil || restart {
		t.Fatalf("Configure stopped = restart %t, err %v", restart, err)
	}
	cfg, err := config.ReadSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SSH || !cfg.DevContainers || cfg.MemMB != memMB || cfg.VCPUs != vcpus {
		t.Fatalf("persisted configure = %+v", cfg)
	}
}

func TestConfigureMCPRemoteExplainsLegacyDaemon(t *testing.T) {
	useShortGantryHome(t)
	captured := fakeLiveSandbox(t, "legacy-mcp", `{"error":"unknown op"}`)
	err := ConfigureMCPRemote("legacy-mcp", "name=api,url=https://example.com/mcp,allow=*", false)
	if err == nil || !strings.Contains(err.Error(), `restart sandbox "legacy-mcp"`) || !strings.Contains(err.Error(), "upgrade its daemon") {
		t.Fatalf("ConfigureMCPRemote = %v, want an actionable daemon-upgrade error", err)
	}
	req := <-captured
	if req.Op != "mcp.remote.set" || req.MCP == nil {
		t.Fatalf("legacy daemon request = %#v", req)
	}
}

// TestSetNetworkPolicyStoppedSandboxWritesStore covers the offline path:
// no daemon anywhere, the policy is validated and persisted for next boot.
func TestSetNetworkPolicyStoppedSandboxWritesStore(t *testing.T) {
	useShortGantryHome(t)
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

// TestSetResourcesWhileLaunchLockHeld mirrors the net-policy guard: a
// launcher mid-boot holds the launch lock, so the stopped-sandbox store
// write must refuse rather than persist an allocation the booting daemon
// will never observe.
func TestSetResourcesWhileLaunchLockHeld(t *testing.T) {
	useShortGantryHome(t)
	writeSandboxConfig(t, "booting")
	lock, err := layout.HoldLaunchLock("booting")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	err = SetResources("booting", 2048, 2, "off")
	if err == nil || !strings.Contains(err.Error(), "launching") {
		t.Fatalf("SetResources = %v, want a launching conflict", err)
	}
	cfg, cfgErr := config.ReadSandboxConfig(layout.Dir("booting"))
	if cfgErr != nil {
		t.Fatal(cfgErr)
	}
	if cfg.MemMB != 512 || cfg.VCPUs != 1 {
		t.Fatalf("config changed under a held launch lock: %+v", cfg)
	}
}

// TestSetNetworkPolicyWhileLaunchLockHeld: a launcher holding the launch
// lock means a daemon may be mid-boot reading sandbox.json. The stopped
// path must refuse to write instead of silently losing the update.
func TestShareAndSecretMutationsWhileLaunchLockHeld(t *testing.T) {
	useShortGantryHome(t)
	dir := writeSandboxConfig(t, "booting")
	store, err := config.LoadConfigStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSecretName("TOKEN", true); err != nil {
		t.Fatal(err)
	}
	lock, err := layout.HoldLaunchLock("booting")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := ConfigureShare("booting", "code="+t.TempDir(), false); err == nil || !strings.Contains(err.Error(), "launching") {
		t.Fatalf("ConfigureShare = %v, want launching conflict", err)
	}
	if err := RemoveSecret("booting", "TOKEN"); err == nil || !strings.Contains(err.Error(), "launching") {
		t.Fatalf("RemoveSecret = %v, want launching conflict", err)
	}
	cfg, err := config.ReadSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 0 || len(cfg.SecretNames) != 1 || cfg.SecretNames[0] != "TOKEN" {
		t.Fatalf("config changed under launch lock: %+v", cfg)
	}
}

func TestSetNetworkPolicyWhileLaunchLockHeld(t *testing.T) {
	useShortGantryHome(t)
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
