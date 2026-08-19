package control

import (
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
)

// newTestConfigStore writes a minimal valid sandbox.json into dir and opens a
// store over it. The managers take a store rather than a path, so their tests
// need one without booting a daemon.
func newTestConfigStore(t *testing.T, dir string, cfg config.RunConfig) *config.ConfigStore {
	t.Helper()
	if cfg.MemMB == 0 {
		cfg.MemMB = 512
	}
	if cfg.VCPUs == 0 {
		cfg.VCPUs = 1
	}
	if err := config.WriteSandboxConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadConfigStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
