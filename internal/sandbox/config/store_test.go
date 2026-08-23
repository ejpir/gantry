package config

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
	"github.com/ejpir/gantry/internal/secret"
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
	cfg, err := ReadSandboxConfig(dir)
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
	cfg, _ = ReadSandboxConfig(dir)
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
	cfg, readErr := ReadSandboxConfig(dir)
	if readErr != nil || len(cfg.Ports) != 2 {
		t.Fatalf("committed on-disk config = %+v, err = %v", cfg, readErr)
	}
}

func TestConfigStoreSnapshotDoesNotAliasState(t *testing.T) {
	dir := t.TempDir()
	enabled := true
	custody := true
	store := newTestConfigStore(t, dir, RunConfig{
		Shares:      []string{"code=/tmp/code"},
		Ports:       []string{"127.0.0.1:8080:80"},
		SecretNames: []string{"TOKEN"},
		MCPRemotes:  []string{"name=api,url=https://example.com,allow=*"},
		SecretSources: []secret.NamedSource{{
			Name: "TOKEN", Source: secret.Source{Kind: secret.SourceExec, Argv: []string{"helper", "arg"}},
		}},
		OAuthBridge:  &enabled,
		OAuthCustody: &custody,
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
	snapshot.MCPRemotes[0] = "changed"
	snapshot.SecretSources[0].Name = "changed"
	snapshot.SecretSources[0].Source.Argv[0] = "changed"
	*snapshot.OAuthBridge = false
	*snapshot.OAuthCustody = false
	snapshot.ImageCfg.Env[0] = "changed"
	snapshot.ImageCfg.Entrypoint[0] = "changed"
	snapshot.ImageCfg.Cmd[0] = "changed"
	snapshot.LayerSet.Layers[0] = "changed"

	got := store.Snapshot()
	if got.Shares[0] != "code=/tmp/code" || got.Ports[0] != "127.0.0.1:8080:80" || got.SecretNames[0] != "TOKEN" {
		t.Fatalf("snapshot mutated store slices: %+v", got)
	}
	if !*got.OAuthBridge || !*got.OAuthCustody || got.ImageCfg.Env[0] != "A=1" || got.ImageCfg.Entrypoint[0] != "/bin/app" || got.ImageCfg.Cmd[0] != "serve" {
		t.Fatalf("snapshot mutated nested config: %+v", got)
	}
	if got.MCPRemotes[0] == "changed" || got.SecretSources[0].Name == "changed" || got.SecretSources[0].Source.Argv[0] == "changed" {
		t.Fatalf("snapshot mutated MCP/secret source fields: %+v", got)
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
			VCPUs: MaxSandboxVCPUs() + 1,
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

func TestConfigStoreManagesMCPServersForRestart(t *testing.T) {
	store := newTestConfigStore(t, t.TempDir(), RunConfig{MemMB: 512, VCPUs: 1})
	remote, err := store.SetMCPRemote("name=github,url=https://example.com/mcp,allow=*", false)
	if err != nil {
		t.Fatal(err)
	}
	if remote.Name != "github" || !store.Snapshot().MCP || len(store.Snapshot().MCPRemotes) != 1 {
		t.Fatalf("MCP config after add = %+v", store.Snapshot())
	}
	if _, err := store.SetMCPRemote("name=github,url=https://other.example/mcp,allow=read_*", false); err == nil {
		t.Fatal("duplicate MCP server was accepted without replace")
	}
	if _, err := store.SetMCPRemote("name=github,url=https://other.example/mcp,allow=read_*", true); err != nil {
		t.Fatal(err)
	}
	if got := store.Snapshot().MCPRemotes[0]; !strings.Contains(got, "other.example") || strings.Contains(got, "url=https://example.com") {
		t.Fatalf("replaced MCP remote = %q", got)
	}
	if err := store.SetMCPFilesystem("/workspace/../work", "1000:1000"); err != nil {
		t.Fatal(err)
	}
	if got := store.Snapshot(); got.MCPFSRoot != "/work" || got.MCPFSUser != "1000:1000" {
		t.Fatalf("filesystem MCP config = %+v", got)
	}
	if err := store.RemoveMCPRemote("github"); err != nil {
		t.Fatal(err)
	}
	if got := store.Snapshot(); len(got.MCPRemotes) != 0 || !got.MCP {
		t.Fatalf("MCP config after remote removal = %+v", got)
	}
}

func TestConfigStoreSetResources(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, RunConfig{MemMB: 512, VCPUs: 1, Shares: []string{"code=/tmp"}, ProcessIsolation: "required"})
	vcpus := min(4, MaxSandboxVCPUs())
	if err := store.SetResources(4096, vcpus, ""); err != nil {
		t.Fatal(err)
	}
	cfg, err := ReadSandboxConfig(dir)
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
	if err := store.SetResources(4096, MaxSandboxVCPUs()+1, "off"); err == nil {
		t.Fatalf("accepted more than %d CPUs", MaxSandboxVCPUs())
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
	share, err := store.SetShareForRestart("workspace="+host+",mount=/Users/eh04xk,uid=1000,gid=1000", false)
	if err != nil {
		t.Fatal(err)
	}
	if share.CtrPath != "/Users/eh04xk" {
		t.Fatalf("container path = %q", share.CtrPath)
	}
	cfg, err := ReadSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 1 || cfg.Shares[0] != "workspace="+share.Path+",mount=/Users/eh04xk,uid=1000,gid=1000" || len(cfg.Ports) != 1 {
		t.Fatalf("persisted config = %+v", cfg)
	}
	if _, err := store.SetShareForRestart("workspace="+host+",mount=/workspace", false); err == nil {
		t.Fatal("duplicate tag did not require replace")
	}
	if _, err := store.SetShareForRestart("workspace="+host+",mount=/workspace", true); err != nil {
		t.Fatal(err)
	}
	if got := store.Snapshot().Shares; len(got) != 1 || got[0] != "workspace="+share.Path+",mount=/workspace" {
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
		Shares: []string{"code=/tmp/code,ro", "data=/tmp/data,mount=/workspace"},
		Ports:  []string{"127.0.0.1:8080:80"},
	})
	removed, err := store.RemoveShareForRestart("code")
	if err != nil {
		t.Fatal(err)
	}
	if removed.Tag != "code" || !removed.RO {
		t.Fatalf("removed share = %+v", removed)
	}
	cfg, err := ReadSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 1 || cfg.Shares[0] != "data=/tmp/data,mount=/workspace" || len(cfg.Ports) != 1 {
		t.Fatalf("persisted config = %+v", cfg)
	}
	if _, err := store.RemoveShareForRestart("missing"); err == nil {
		t.Fatal("missing share removal succeeded")
	}
	if got := store.Snapshot().Shares; len(got) != 1 || got[0] != "data=/tmp/data,mount=/workspace" {
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
		if _, err := store.SetShareForRestart("s"+strings.ReplaceAll(alias, "/", "_")+"="+host+",mount="+alias, false); err == nil {
			t.Errorf("alias %q must be rejected (hub overlap)", alias)
		}
	}
	if _, err := store.SetShareForRestart("code="+host+",mount=/host/code", false); err != nil {
		t.Errorf("unrelated alias must pass: %v", err)
	}
}

func TestValidateSandboxResourcesMemCap(t *testing.T) {
	if err := ValidateSandboxResources(uint(MinSandboxMemMB), 1); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSandboxResources(uint(MinSandboxMemMB-1), 1); err == nil {
		t.Fatal("memory below the boot-layout minimum must be rejected")
	}
	if err := ValidateSandboxResources(uint(MaxSandboxMemMB+1), 1); err == nil {
		t.Fatal("memory above the cap must be rejected")
	}
	if err := ValidateSandboxResources(512, MaxSandboxVCPUs()+1); err == nil {
		t.Fatal("vcpus above the cap must be rejected")
	}
}

func TestSetSecretNameBindingAware(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, RunConfig{SecretNames: []string{"TOKEN@git.test"}})
	// Update by clean name: the binding survives (use does not imply rebind).
	if err := store.SetSecretName("TOKEN", true); err != nil {
		t.Fatal(err)
	}
	if got := store.Snapshot().SecretNames; len(got) != 1 || got[0] != "TOKEN@git.test" {
		t.Fatalf("after update: %v", got)
	}
	// Removal by clean name drops the bound entry too.
	if err := store.SetSecretName("TOKEN", false); err != nil {
		t.Fatal(err)
	}
	if got := store.Snapshot().SecretNames; len(got) != 0 {
		t.Fatalf("after remove: %v", got)
	}
}
