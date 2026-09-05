package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/sharefs"
	"github.com/ejpir/gantry/internal/shares"
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

func canonicalTestPath(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
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

func TestConfigurationTransactionSkipsExactNoop(t *testing.T) {
	store := newTestConfigStore(t, t.TempDir(), RunConfig{Runtime: "crun", MemMB: 512, VCPUs: 1})
	writes := 0
	store.SetWriter(func(string, []byte, os.FileMode) error {
		writes++
		return nil
	})
	disabled := false
	tx, err := store.BeginConfiguration(SandboxUpdate{SSH: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if writes != 0 || tx.Changed() || tx.Before().SSH || tx.After().SSH || tx.After().SettingsRevision != 0 {
		t.Fatalf("no-op transaction = writes %d changed %t before %+v after %+v",
			writes, tx.Changed(), tx.Before(), tx.After())
	}
}

func TestConfigurationTransactionRollsBackCompleteSettingsRevision(t *testing.T) {
	store := newTestConfigStore(t, t.TempDir(), RunConfig{SSH: true, Runtime: "crun", MemMB: 512, VCPUs: 1})
	enabled := true
	profileConfig := &image.Config{User: "gantry", Env: []string{"HOME=/home/gantry"}}
	tx, err := store.BeginConfiguration(SandboxUpdate{
		DevContainers: &enabled,
		DevContainersProfile: &DevContainersProfileUpdate{
			Image: "/ide.erofs", ImageCfg: profileConfig, RWLayer: "/ide.ext4", DiskMiB: 8192,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := store.Snapshot(); !got.DevContainers || got.SettingsRevision != 1 {
		t.Fatalf("committed settings = %+v", got)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	got := store.Snapshot()
	if got.DevContainers || got.DevContainersImage != "" || got.DevContainersImageCfg != nil ||
		got.DevContainersRWLayer != "" || got.DevContainersDiskMiB != 0 || got.SettingsRevision != 2 {
		t.Fatalf("rollback retained prepared profile or stale revision: %+v", got)
	}
}

func TestConfigurationTransactionSerializesSettingsAndPreservesUnrelatedMutations(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, RunConfig{Runtime: "crun", MemMB: 512, VCPUs: 1})
	enableSSH := true
	requestedMemory := uint(1024)
	resourceStarted := make(chan struct{})
	resourceDone := make(chan error, 1)

	tx, err := store.BeginConfiguration(SandboxUpdate{SSH: &enableSSH, MemMB: &requestedMemory})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Unrelated mutations remain available while service reconciliation is in
	// flight and must survive a complete settings rollback.
	if err := store.Mutate(func(cfg *RunConfig) error {
		cfg.Ports = append(cfg.Ports, "127.0.0.1:8080:80")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Independent resource settings wait for transaction ownership even when
	// they select the same value as the revision being rolled back.
	go func() {
		close(resourceStarted)
		resourceDone <- store.SetResources(requestedMemory, 2, "auto")
	}()
	<-resourceStarted
	select {
	case err := <-resourceDone:
		t.Fatalf("resource update escaped configuration transaction: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	tx.Close()

	select {
	case err := <-resourceDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("serialized resource update did not complete")
	}

	got := store.Snapshot()
	if got.SSH || got.MemMB != requestedMemory || got.VCPUs != 2 || got.ProcessIsolation != "auto" || got.SettingsRevision != 3 {
		t.Fatalf("final settings = SSH %t, memory %d, CPUs %d, isolation %q, revision %d",
			got.SSH, got.MemMB, got.VCPUs, got.ProcessIsolation, got.SettingsRevision)
	}
	if len(got.Ports) != 1 || got.Ports[0] != "127.0.0.1:8080:80" {
		t.Fatalf("rollback erased unrelated mutation: %+v", got.Ports)
	}
	persisted, readErr := ReadSandboxConfig(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if persisted.SSH != got.SSH || persisted.MemMB != got.MemMB || persisted.VCPUs != got.VCPUs ||
		persisted.SettingsRevision != got.SettingsRevision || len(persisted.Ports) != 1 {
		t.Fatalf("memory/disk transaction state diverged: memory=%+v disk=%+v", got, persisted)
	}
}

func TestConfigurationTransactionCommitMergesUnrelatedPreparationMutation(t *testing.T) {
	store := newTestConfigStore(t, t.TempDir(), RunConfig{Runtime: "crun", MemMB: 512, VCPUs: 1})
	enabled := true
	tx, err := store.BeginConfiguration(SandboxUpdate{SSH: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if err := store.Mutate(func(cfg *RunConfig) error {
		cfg.Ports = append(cfg.Ports, "127.0.0.1:8080:80")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got := store.Snapshot()
	if !got.SSH || got.SettingsRevision != 1 || len(got.Ports) != 1 || got.Ports[0] != "127.0.0.1:8080:80" {
		t.Fatalf("merged transaction = %+v", got)
	}
}

func TestConfigurationTransactionRejectsStaleSettingsRevision(t *testing.T) {
	store := newTestConfigStore(t, t.TempDir(), RunConfig{Runtime: "crun", MemMB: 512, VCPUs: 1})
	enabled := true
	tx, err := store.BeginConfiguration(SandboxUpdate{SSH: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	// General mutations are allowed during preparation, but changing a setting
	// through that legacy path advances the revision and invalidates the plan.
	if err := store.Mutate(func(cfg *RunConfig) error {
		cfg.MemMB = 1024
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); !errors.Is(err, ErrConfigurationConflict) {
		t.Fatalf("Commit error = %v, want revision conflict", err)
	}
	if got := store.Snapshot(); got.SSH || got.MemMB != 1024 || got.SettingsRevision != 1 {
		t.Fatalf("stale commit changed settings: %+v", got)
	}
}

func TestConfigStoreSnapshotDoesNotAliasState(t *testing.T) {
	dir := t.TempDir()
	enabled := true
	custody := true
	store := newTestConfigStore(t, dir, RunConfig{
		Shares:      []string{"code=/tmp/code,ro"},
		Ports:       []string{"127.0.0.1:8080:80"},
		SecretNames: []string{"TOKEN"},
		MCPRemotes:  []string{"name=api,url=https://example.com,allow=*"},
		SecretSources: []secret.NamedSource{{
			Name: "TOKEN", Source: secret.Source{Kind: secret.SourceEnv, Ref: "TOKEN", Argv: []string{"helper", "arg"}},
		}},
		OAuthBridge:  &enabled,
		OAuthCustody: &custody,
		ImageCfg: &image.Config{
			Env:        []string{"A=1"},
			Entrypoint: []string{"/bin/app"},
			Cmd:        []string{"serve"},
		},
		DevContainersImageCfg: &image.Config{
			Env: []string{"HOME=/home/gantry"}, Cmd: []string{"/bin/bash"},
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
	snapshot.DevContainersImageCfg.Env[0] = "changed"
	snapshot.DevContainersImageCfg.Cmd[0] = "changed"
	snapshot.LayerSet.Layers[0] = "changed"

	got := store.Snapshot()
	if got.Shares[0] != "code=/tmp/code,ro" || got.Ports[0] != "127.0.0.1:8080:80" || got.SecretNames[0] != "TOKEN" {
		t.Fatalf("snapshot mutated store slices: %+v", got)
	}
	if !*got.OAuthBridge || !*got.OAuthCustody || got.ImageCfg.Env[0] != "A=1" || got.ImageCfg.Entrypoint[0] != "/bin/app" || got.ImageCfg.Cmd[0] != "serve" ||
		got.DevContainersImageCfg.Env[0] != "HOME=/home/gantry" || got.DevContainersImageCfg.Cmd[0] != "/bin/bash" {
		t.Fatalf("snapshot mutated nested config: %+v", got)
	}
	if got.MCPRemotes[0] == "changed" || got.SecretSources[0].Name == "changed" || got.SecretSources[0].Source.Argv[0] == "changed" {
		t.Fatalf("snapshot mutated MCP/secret source fields: %+v", got)
	}
	if got.LayerSet.Layers[0] != "layer" {
		t.Fatalf("snapshot mutated layer set: %+v", got.LayerSet)
	}
}

func TestConfigStoreRejectsHostExecSecretSource(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, RunConfig{})

	err := store.Mutate(func(cfg *RunConfig) error {
		cfg.SecretSources = []secret.NamedSource{{
			Name: "TOKEN", Source: secret.Source{Kind: secret.SourceExec, Argv: []string{"credential-helper", "token"}},
		}}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "is disabled") {
		t.Fatalf("host exec source mutation error = %v", err)
	}
	if got := store.Snapshot().SecretSources; len(got) != 0 {
		t.Fatalf("rejected source persisted: %v", got)
	}
}

func TestReadSandboxConfigRejectsPersistedExecSourceWithWritableShare(t *testing.T) {
	dir := t.TempDir()
	cfg := RunConfig{
		Kernel: "/kernel", Rootfs: "/rootfs", Image: "/image", MemMB: 512, VCPUs: 1,
		SecretSources: []secret.NamedSource{{
			Name: "TOKEN", Source: secret.Source{Kind: secret.SourceExec, Argv: []string{"helper"}},
		}},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSandboxConfig(dir); err == nil || !strings.Contains(err.Error(), "is disabled") {
		t.Fatalf("persisted unsafe configuration error = %v", err)
	}
}

func TestValidateSecretSourceIsolationRejectsFileSourceInsideWritableShare(t *testing.T) {
	shareRoot := t.TempDir()
	secretPath := filepath.Join(shareRoot, "token")
	if err := os.WriteFile(secretPath, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	secretPath = canonicalTestPath(t, secretPath)
	cfg := RunConfig{
		Shares: []string{"code=" + shareRoot},
		SecretSources: []secret.NamedSource{{
			Name: "TOKEN", Source: secret.Source{Kind: secret.SourceFile, Ref: secretPath},
		}},
	}
	if err := ValidateSecretSourceIsolation(cfg); err == nil || !strings.Contains(err.Error(), "link to another host file") {
		t.Fatalf("file source inside writable share error = %v", err)
	}

	cfg.Shares[0] += ",ro"
	if err := ValidateSecretSourceIsolation(cfg); err != nil {
		t.Fatalf("file source inside read-only share should be safe: %v", err)
	}
	cfg.Shares = []string{"code=" + t.TempDir()}
	if err := ValidateSecretSourceIsolation(cfg); err != nil {
		t.Fatalf("unrelated writable share should remain compatible with file source: %v", err)
	}

	if runtime.GOOS != "windows" {
		aliasParent := t.TempDir()
		alias := filepath.Join(aliasParent, "share-alias")
		if err := os.Symlink(shareRoot, alias); err != nil {
			t.Fatal(err)
		}
		cfg.Shares = []string{"code=" + alias}
		if err := ValidateSecretSourceIsolation(cfg); err == nil || !strings.Contains(err.Error(), "link to another host file") {
			t.Fatalf("aliased writable share error = %v", err)
		}
	}
}

func TestValidateSecretSourceIsolationFailsClosedForUnresolvedFileSource(t *testing.T) {
	shareRoot := t.TempDir()
	missing := filepath.Join(t.TempDir(), "future", "token")
	cfg := RunConfig{
		Shares: []string{"code=" + shareRoot},
		SecretSources: []secret.NamedSource{{
			Name: "TOKEN", Source: secret.Source{Kind: secret.SourceFile, Ref: missing},
		}},
	}
	if err := ValidateSecretSourceIsolation(cfg); err == nil || !strings.Contains(err.Error(), "must exist") {
		t.Fatalf("missing file source error = %v", err)
	}

	if runtime.GOOS != "windows" {
		alias := filepath.Join(t.TempDir(), "token-link")
		if err := os.Symlink(filepath.Join(shareRoot, "future", "token"), alias); err != nil {
			t.Fatal(err)
		}
		cfg.SecretSources[0].Source.Ref = alias
		if err := ValidateSecretSourceIsolation(cfg); err == nil || !strings.Contains(err.Error(), "must exist") {
			t.Fatalf("dangling alias into writable share error = %v", err)
		}
	}
}

func TestValidateSecretSourceIsolationRequiresStableFilePathSyntax(t *testing.T) {
	sep := string(filepath.Separator)
	for _, ref := range []string{"relative/token", sep + "safe" + sep + "dir" + sep + ".." + sep + "token"} {
		cfg := RunConfig{
			Shares: []string{"code=" + t.TempDir()},
			SecretSources: []secret.NamedSource{{
				Name: "TOKEN", Source: secret.Source{Kind: secret.SourceFile, Ref: ref},
			}},
		}
		if err := ValidateSecretSourceIsolation(cfg); err == nil {
			t.Fatalf("file source path %q unexpectedly accepted", ref)
		}
	}
	legacy := RunConfig{SecretSources: []secret.NamedSource{{
		Name: "TOKEN", Source: secret.Source{Kind: secret.SourceFile, Ref: "relative/token"},
	}}}
	if err := ValidateSecretSourceIsolation(legacy); err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("legacy relative source error = %v", err)
	}
}

func TestValidateSecretSourcePinnedShareUsesPreparedIdentity(t *testing.T) {
	shareRoot := t.TempDir()
	secretPath := filepath.Join(shareRoot, "token")
	if err := os.WriteFile(secretPath, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	secretPath = canonicalTestPath(t, secretPath)
	identity, err := sharefs.Identify(shareRoot)
	if err != nil {
		t.Fatal(err)
	}
	source := []secret.NamedSource{{
		Name: "TOKEN", Source: secret.Source{Kind: secret.SourceFile, Ref: secretPath},
	}}
	// The pathname is deliberately unrelated: this models a symlink swap
	// after pre-validation but before PrepareMapped pins its actual root.
	share := shares.Spec{Tag: "code", Path: t.TempDir()}
	if err := ValidateSecretSourcePinnedShare(source, share, identity); err == nil || !strings.Contains(err.Error(), "link to another host file") {
		t.Fatalf("pinned share identity error = %v", err)
	}
}

func TestValidateSecretSourceIsolationRejectsExecInEverySandbox(t *testing.T) {
	execSource := []secret.NamedSource{{
		Name: "TOKEN", Source: secret.Source{Kind: secret.SourceExec, Argv: []string{"helper"}},
	}}
	for _, cfg := range []RunConfig{
		{SecretSources: execSource},
		{RW: true, RWLayer: "/work.ext4", SecretSources: execSource},
		{DevContainers: true, DevContainersRWLayer: "/ide.ext4", SecretSources: execSource},
	} {
		if err := ValidateSecretSourceIsolation(cfg); err == nil || !strings.Contains(err.Error(), "is disabled") {
			t.Fatalf("host exec source error = %v", err)
		}
	}
}

func TestValidateDevContainersFailsClosed(t *testing.T) {
	valid := RunConfig{DevContainers: true, SSH: true, RW: true, RWLayer: "/tmp/dev.ext4", Runtime: "crun"}
	if err := ValidateDevContainers(valid); err != nil {
		t.Fatalf("valid profile: %v", err)
	}
	legacy := valid
	legacy.Runtime = ""
	if err := ValidateDevContainers(legacy); err != nil {
		t.Fatalf("legacy default-crun profile: %v", err)
	}
	readOnlyWorkload := valid
	readOnlyWorkload.RW, readOnlyWorkload.RWLayer = false, ""
	if err := ValidateDevContainers(readOnlyWorkload); err != nil {
		t.Fatalf("read-only workload with peer IDE profile: %v", err)
	}
	for name, mutate := range map[string]func(*RunConfig){
		"SSH disabled":   func(cfg *RunConfig) { cfg.SSH = false },
		"gVisor runtime": func(cfg *RunConfig) { cfg.Runtime = "runsc" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			mutate(&cfg)
			if err := ValidateDevContainers(cfg); err == nil {
				t.Fatalf("accepted unsafe config: %+v", cfg)
			}
		})
	}
}

func TestApplySandboxUpdateEnablesDevContainers(t *testing.T) {
	cfg := RunConfig{MemMB: 512, VCPUs: 1, RW: true, RWLayer: "/tmp/dev.ext4", Runtime: "crun"}
	ssh, devContainers := true, true
	memMB, vcpus := uint(4096), min(4, MaxSandboxVCPUs())
	if err := ApplySandboxUpdate(&cfg, SandboxUpdate{
		SSH: &ssh, DevContainers: &devContainers, MemMB: &memMB, VCPUs: &vcpus,
	}); err != nil {
		t.Fatal(err)
	}
	if !cfg.SSH || !cfg.DevContainers || cfg.MemMB != memMB || cfg.VCPUs != vcpus || cfg.DevContainersDiskMiB != DefaultDevContainersDiskSizeMiB {
		t.Fatalf("updated config = %+v", cfg)
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
	host := t.TempDir()
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

func TestConfigStoreRejectsShareOverlappingSandboxState(t *testing.T) {
	for _, target := range []string{"state directory", "state parent", "state child"} {
		t.Run(target, func(t *testing.T) {
			stateParent := t.TempDir()
			stateDir := filepath.Join(stateParent, "sandbox")
			if err := os.Mkdir(stateDir, 0o700); err != nil {
				t.Fatal(err)
			}
			store := newTestConfigStore(t, stateDir, RunConfig{})
			sharePath := stateDir
			switch target {
			case "state parent":
				sharePath = stateParent
			case "state child":
				sharePath = filepath.Join(stateDir, "child")
				if err := os.Mkdir(sharePath, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.SetShareForRestart("state="+sharePath, false); err == nil || !strings.Contains(err.Error(), "state root") {
				t.Fatalf("state-overlapping share error = %v", err)
			}
			if got := store.Snapshot().Shares; len(got) != 0 {
				t.Fatalf("rejected share changed configuration: %v", got)
			}
		})
	}
}

func TestConfigStoreRejectsReadOnlyInternalStateShare(t *testing.T) {
	stateDir := t.TempDir()
	stageDir := filepath.Join(stateDir, "guest-tools-stage")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store := newTestConfigStore(t, stateDir, RunConfig{})
	if _, err := store.SetShareForRestart("tools="+stageDir+",ro", false); err == nil || !strings.Contains(err.Error(), "state root") {
		t.Fatalf("read-only internal state share error = %v", err)
	}
	if got := store.Snapshot().Shares; len(got) != 0 {
		t.Fatalf("rejected share changed configuration: %v", got)
	}
}

func TestConfigStoreRejectsSiblingSandboxStateShare(t *testing.T) {
	appRoot := t.TempDir()
	root := filepath.Join(appRoot, "sandboxes")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GANTRY_HOME", root)
	stateDir := filepath.Join(root, "alpha")
	siblingDir := filepath.Join(root, "beta")
	sshStateDir := filepath.Join(appRoot, "ssh")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(siblingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sshStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store := newTestConfigStore(t, stateDir, RunConfig{})
	for tag, path := range map[string]string{"sibling": siblingDir, "sshstate": sshStateDir} {
		if _, err := store.SetShareForRestart(tag+"="+path, false); err == nil || !strings.Contains(err.Error(), "Gantry state root") {
			t.Fatalf("%s restart share error = %v", tag, err)
		}
	}
	if got := store.Snapshot().Shares; len(got) != 0 {
		t.Fatalf("rejected sibling share changed configuration: %v", got)
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
	host := t.TempDir()
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
