package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
)

func TestConfigurePersistsRuntimeNormalizationOnOtherwiseNoopUpdate(t *testing.T) {
	dir := t.TempDir()
	initial := config.RunConfig{
		SSH: true, DevContainers: true, RW: true,
		RWLayer: filepath.Join(dir, "rw.ext4"), MemMB: 4096, VCPUs: 2,
	}
	data, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadConfigStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	daemon := &daemonRuntime{store: store, broker: &broker{}}
	restart, err := daemon.configureSandbox(controlproto.ConfigureRequest{
		SSH: &enabled, DevContainers: &enabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if restart {
		t.Fatal("runtime normalization unexpectedly requires VM restart")
	}
	persisted, err := config.ReadSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Runtime != "crun" {
		t.Fatalf("persisted runtime = %q, want crun", persisted.Runtime)
	}
}
