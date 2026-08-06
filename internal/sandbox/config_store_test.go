package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestConfigStore writes sandbox.json for cfg and opens its store — the
// same construction order the daemon uses.
func newTestConfigStore(t *testing.T, dir string, cfg RunConfig) *ConfigStore {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadConfigStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestConfigStoreMutateRollback(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, RunConfig{RW: true, Ports: []string{"127.0.0.1:8080:80"}})

	// Failed mutations leave memory and disk untouched.
	boom := os.ErrPermission
	if err := store.Mutate(func(cfg *RunConfig) error {
		cfg.Ports = append(cfg.Ports, "127.0.0.1:9090:90")
		cfg.Shares = append(cfg.Shares, "data=/tmp")
		return boom
	}); err != boom {
		t.Fatalf("mutate error = %v", err)
	}
	snap := store.Snapshot()
	if len(snap.Ports) != 1 || len(snap.Shares) != 0 {
		t.Fatalf("failed mutation leaked into memory: %+v", snap)
	}
	cfg, err := readSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Ports) != 1 || len(cfg.Shares) != 0 {
		t.Fatalf("failed mutation leaked onto disk: %+v", cfg)
	}

	// Successful mutations persist and do not alias the store's slices.
	if err := store.Mutate(func(cfg *RunConfig) error {
		cfg.Shares = append(cfg.Shares, "data=/tmp")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cfg, _ = readSandboxConfig(dir)
	if len(cfg.Shares) != 1 || cfg.Shares[0] != "data=/tmp" || len(cfg.Ports) != 1 {
		t.Fatalf("persisted config: %+v", cfg)
	}
}

func TestConfigStoreLoadCorrupt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigStore(dir); err == nil {
		t.Fatal("corrupt sandbox.json loaded without error")
	}
}

func TestConfigStoreSetResources(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, RunConfig{MemMB: 512, VCPUs: 1, Shares: []string{"code=/tmp"}})
	if err := store.SetResources(4096, 4); err != nil {
		t.Fatal(err)
	}
	cfg, err := readSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MemMB != 4096 || cfg.VCPUs != 4 || len(cfg.Shares) != 1 {
		t.Fatalf("persisted resources = %+v", cfg)
	}
	if err := store.SetResources(4096, 9); err == nil {
		t.Fatal("accepted more than 8 CPUs")
	}
	if got := store.Snapshot(); got.MemMB != 4096 || got.VCPUs != 4 {
		t.Fatalf("invalid mutation changed store: %+v", got)
	}
}

func TestConfigStoreSetShareForRestart(t *testing.T) {
	dir := t.TempDir()
	host := filepath.Join(dir, "host")
	if err := os.Mkdir(host, 0o700); err != nil {
		t.Fatal(err)
	}
	store := newTestConfigStore(t, dir, RunConfig{Ports: []string{"127.0.0.1:8080:80"}})
	share, err := store.SetShareForRestart("workspace="+host+"@/Users/eh04xk,uid=1000,gid=1000", false)
	if err != nil {
		t.Fatal(err)
	}
	if share.CtrPath != "/Users/eh04xk" {
		t.Fatalf("container path = %q", share.CtrPath)
	}
	cfg, err := readSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 1 || cfg.Shares[0] != "workspace="+share.Path+"@/Users/eh04xk,uid=1000,gid=1000" || len(cfg.Ports) != 1 {
		t.Fatalf("persisted config = %+v", cfg)
	}
	if _, err := store.SetShareForRestart("workspace="+host+"@/workspace", false); err == nil {
		t.Fatal("duplicate tag did not require replace")
	}
	if _, err := store.SetShareForRestart("workspace="+host+"@/workspace", true); err != nil {
		t.Fatal(err)
	}
	if got := store.Snapshot().Shares; len(got) != 1 || got[0] != "workspace="+share.Path+"@/workspace" {
		t.Fatalf("replacement = %v", got)
	}
}

func TestConfigStoreShareRestartHubConfinement(t *testing.T) {
	// regression: the hub guard was exact-equality only; a container alias
	// that is a parent (/run/gantry, /) or child of the hub mount shadows
	// (or is shadowed by) the hub FUSE mount.
	dir := t.TempDir()
	host := filepath.Join(dir, "host")
	if err := os.Mkdir(host, 0o700); err != nil {
		t.Fatal(err)
	}
	store := newTestConfigStore(t, dir, RunConfig{})
	for _, alias := range []string{"/run/gantry/shares", "/run/gantry", "/run", "/", "/run/gantry/shares/x"} {
		if _, err := store.SetShareForRestart("s"+strings.ReplaceAll(alias, "/", "_")+"="+host+"@"+alias, false); err == nil {
			t.Errorf("alias %q must be rejected (hub overlap)", alias)
		}
	}
	if _, err := store.SetShareForRestart("code="+host+"@/host/code", false); err != nil {
		t.Errorf("unrelated alias must pass: %v", err)
	}
}

func TestValidateSandboxResourcesMemCap(t *testing.T) {
	if err := validateSandboxResources(1, 1); err != nil {
		t.Fatal(err)
	}
	if err := validateSandboxResources(maxSandboxMemMB+1, 1); err == nil {
		t.Fatal("memory above the cap must be rejected")
	}
	if err := validateSandboxResources(512, maxSandboxVCPUs+1); err == nil {
		t.Fatal("vcpus above the cap must be rejected")
	}
}
