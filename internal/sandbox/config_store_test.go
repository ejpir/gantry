package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
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
