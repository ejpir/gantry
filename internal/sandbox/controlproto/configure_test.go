package controlproto

import (
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
)

func TestConfigureRequestSettingsRoundTrip(t *testing.T) {
	settings := config.MutableSandboxSettings{
		SSH: true, DevContainers: true, MemMB: 4096,
		VCPUs: min(4, config.MaxSandboxVCPUs()), ProcessIsolation: "required",
	}
	request := ConfigureRequestFor(settings)
	update := request.SandboxUpdate()
	cfg := config.RunConfig{Runtime: "crun", MemMB: 512, VCPUs: 1}
	if err := config.ApplySandboxUpdate(&cfg, update); err != nil {
		t.Fatal(err)
	}
	if cfg.SSH != settings.SSH || cfg.DevContainers != settings.DevContainers ||
		cfg.MemMB != settings.MemMB || cfg.VCPUs != settings.VCPUs ||
		cfg.ProcessIsolation != settings.ProcessIsolation {
		t.Fatalf("round-trip settings = %+v, want %+v", cfg, settings)
	}
}

func TestConfigureRequestSandboxUpdatePreservesOmittedFields(t *testing.T) {
	enabled := true
	update := (ConfigureRequest{SSH: &enabled}).SandboxUpdate()
	if update.SSH == nil || !*update.SSH || update.DevContainers != nil || update.MemMB != nil ||
		update.VCPUs != nil || update.ProcessIsolation != nil {
		t.Fatalf("partial update = %+v", update)
	}
}
