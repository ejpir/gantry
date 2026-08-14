package sandbox

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/image"
)

// newTestConfigStore writes sandbox.json for cfg and opens its store — the
// same construction order the daemon uses.
func newTestConfigStore(t *testing.T, dir string, cfg RunConfig) *ConfigStore {
	t.Helper()
	if cfg.MemMB == 0 {
		cfg.MemMB = 512
	}
	if cfg.VCPUs == 0 {
		cfg.VCPUs = 1
	}
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

func TestConfigStoreKeepsPostCommitState(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, RunConfig{Ports: []string{"127.0.0.1:8080:80"}})
	wantErr := errors.New("directory sync failed")
	store.write = func(path string, data []byte, mode os.FileMode) error {
		if err := os.WriteFile(path, data, mode); err != nil {
			return err
		}
		return &atomicfile.CommitError{Err: wantErr}
	}

	err := store.Mutate(func(cfg *RunConfig) error {
		cfg.Ports = append(cfg.Ports, "127.0.0.1:9090:90")
		return nil
	})
	if !atomicfile.Committed(err) || !errors.Is(err, wantErr) {
		t.Fatalf("mutation error = %v, want committed error", err)
	}
	if got := store.Snapshot().Ports; len(got) != 2 {
		t.Fatalf("committed in-memory ports = %v", got)
	}
	cfg, readErr := readSandboxConfig(dir)
	if readErr != nil || len(cfg.Ports) != 2 {
		t.Fatalf("committed on-disk config = %+v, err = %v", cfg, readErr)
	}
}

func TestConfigStoreSnapshotDoesNotAliasState(t *testing.T) {
	dir := t.TempDir()
	enabled := true
	store := newTestConfigStore(t, dir, RunConfig{
		Shares:      []string{"code=/tmp/code"},
		Ports:       []string{"127.0.0.1:8080:80"},
		SecretNames: []string{"TOKEN"},
		OAuthBridge: &enabled,
		ImageCfg: &image.Config{
			Env:        []string{"A=1"},
			Entrypoint: []string{"/bin/app"},
			Cmd:        []string{"serve"},
		},
		LayerSet: &client.LayerSet{FSMeta: "meta", Layers: []string{"layer"}},
	})

	snapshot := store.Snapshot()
	snapshot.Shares[0] = "changed"
	snapshot.Ports[0] = "changed"
	snapshot.SecretNames[0] = "changed"
	*snapshot.OAuthBridge = false
	snapshot.ImageCfg.Env[0] = "changed"
	snapshot.ImageCfg.Entrypoint[0] = "changed"
	snapshot.ImageCfg.Cmd[0] = "changed"
	snapshot.LayerSet.Layers[0] = "changed"

	got := store.Snapshot()
	if got.Shares[0] != "code=/tmp/code" || got.Ports[0] != "127.0.0.1:8080:80" || got.SecretNames[0] != "TOKEN" {
		t.Fatalf("snapshot mutated store slices: %+v", got)
	}
	if !*got.OAuthBridge || got.ImageCfg.Env[0] != "A=1" || got.ImageCfg.Entrypoint[0] != "/bin/app" || got.ImageCfg.Cmd[0] != "serve" {
		t.Fatalf("snapshot mutated nested config: %+v", got)
	}
	if got.LayerSet.Layers[0] != "layer" {
		t.Fatalf("snapshot mutated layer set: %+v", got.LayerSet)
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

func TestConfigStoreRejectsInvalidPersistedResources(t *testing.T) {
	for name, cfg := range map[string]RunConfig{
		"zero memory": {VCPUs: 1},
		"zero CPUs":   {MemMB: 512},
		"too many CPUs": {
			MemMB: 512,
			VCPUs: maxSandboxVCPUs + 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfigStore(dir); err == nil {
				t.Fatalf("LoadConfigStore accepted %+v", cfg)
			}
		})
	}
}

func TestConfigStoreSetResources(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, RunConfig{MemMB: 512, VCPUs: 1, Shares: []string{"code=/tmp"}, ProcessIsolation: "required"})
	vcpus := 4
	if runtime.GOOS == "windows" {
		vcpus = 1 // WHPX SMP remains deliberately unavailable.
	}
	if err := store.SetResources(4096, vcpus, ""); err != nil {
		t.Fatal(err)
	}
	cfg, err := readSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MemMB != 4096 || cfg.VCPUs != vcpus || len(cfg.Shares) != 1 || cfg.ProcessIsolation != "required" {
		t.Fatalf("persisted resources = %+v", cfg)
	}
	if err := store.SetResources(4096, vcpus, "off"); err != nil {
		t.Fatal(err)
	}
	if got := store.Snapshot().ProcessIsolation; got != "off" {
		t.Fatalf("process isolation = %q, want off", got)
	}
	if err := store.SetResources(4096, 9, "off"); err == nil {
		t.Fatal("accepted more than 8 CPUs")
	}
	if got := store.Snapshot(); got.MemMB != 4096 || got.VCPUs != vcpus {
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

func TestConfigStoreRejectsDescriptorIdentityAlias(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()
	alias := root
	if runtime.GOOS != "windows" {
		alias = filepath.Join(t.TempDir(), "alias")
		if err := os.Symlink(root, alias); err != nil {
			t.Fatal(err)
		}
	}
	store := newTestConfigStore(t, dir, RunConfig{})
	if _, err := store.SetShareForRestart("root="+root, false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetShareForRestart("alias="+alias, false); err == nil || !strings.Contains(err.Error(), "aliases share root") {
		t.Fatalf("alias configuration error = %v", err)
	}
}

func TestConfigStoreRemoveShareForRestart(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, RunConfig{
		Shares: []string{"code=/tmp/code,ro", "data=/tmp/data@/workspace"},
		Ports:  []string{"127.0.0.1:8080:80"},
	})
	removed, err := store.RemoveShareForRestart("code")
	if err != nil {
		t.Fatal(err)
	}
	if removed.Tag != "code" || !removed.RO {
		t.Fatalf("removed share = %+v", removed)
	}
	cfg, err := readSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 1 || cfg.Shares[0] != "data=/tmp/data@/workspace" || len(cfg.Ports) != 1 {
		t.Fatalf("persisted config = %+v", cfg)
	}
	if _, err := store.RemoveShareForRestart("missing"); err == nil {
		t.Fatal("missing share removal succeeded")
	}
	if got := store.Snapshot().Shares; len(got) != 1 || got[0] != "data=/tmp/data@/workspace" {
		t.Fatalf("failed removal changed shares: %v", got)
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
	if err := validateSandboxResources(uint(minSandboxMemMB), 1); err != nil {
		t.Fatal(err)
	}
	if err := validateSandboxResources(uint(minSandboxMemMB-1), 1); err == nil {
		t.Fatal("memory below the boot-layout minimum must be rejected")
	}
	if err := validateSandboxResources(uint(maxSandboxMemMB+1), 1); err == nil {
		t.Fatal("memory above the cap must be rejected")
	}
	if err := validateSandboxResources(512, maxSandboxVCPUs+1); err == nil {
		t.Fatal("vcpus above the cap must be rejected")
	}
}
