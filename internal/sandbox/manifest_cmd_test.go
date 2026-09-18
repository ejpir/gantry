package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func TestPlanManifestApplyLifecycle(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	desired := &config.ManifestProvenance{APIVersion: "gantry.dev/v1alpha1", Digest: "sha256:desired"}
	plan, current, err := planManifestApply("dev", desired, false)
	if err != nil || plan != manifestCreate || current != nil {
		t.Fatalf("missing plan = %v, current=%+v, error=%v", plan, current, err)
	}

	dir := layout.Dir("dev")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.RunConfig{Manifest: desired, MemMB: 512, VCPUs: 1, Net: true}
	if err := config.WriteSandboxConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	plan, _, err = planManifestApply("dev", desired, false)
	if err != nil || plan != manifestStartSaved {
		t.Fatalf("matching stopped plan = %v, error=%v", plan, err)
	}
	plan, _, err = planManifestApply("dev", desired, true)
	if err != nil || plan != manifestUpdateStopped {
		t.Fatalf("forced stopped plan = %v, error=%v", plan, err)
	}

	drifted := &config.ManifestProvenance{APIVersion: desired.APIVersion, Digest: "sha256:other"}
	plan, _, err = planManifestApply("dev", drifted, false)
	if err != nil || plan != manifestUpdateStopped {
		t.Fatalf("drifted stopped plan = %v, error=%v", plan, err)
	}
}

func TestApplySavedManifestKeepsPreviousConfigOnResolutionFailure(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	name := "preserve"
	dir := layout.Dir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := config.RunConfig{MemMB: 512, VCPUs: 1, Runtime: "crun", ProcessIsolation: "auto"}
	if err := config.WriteSandboxConfig(dir, previous); err != nil {
		t.Fatal(err)
	}
	options := config.DefaultRunOptions()
	options.Runtime = "invalid"
	if _, err := applySavedManifest(context.Background(), name, options, nil); err == nil {
		t.Fatal("invalid replacement unexpectedly succeeded")
	}
	got, err := config.ReadSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Runtime != previous.Runtime || got.MemMB != previous.MemMB || got.VCPUs != previous.VCPUs {
		t.Fatalf("previous configuration changed: %+v", got)
	}
}

func TestPlanManifestApplyDetectsRunningSandbox(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	name := "running"
	dir := layout.Dir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	desired := &config.ManifestProvenance{APIVersion: "gantry.dev/v1alpha1", Digest: "sha256:desired"}
	if err := config.WriteSandboxConfig(dir, config.RunConfig{Manifest: desired, MemMB: 512, VCPUs: 1}); err != nil {
		t.Fatal(err)
	}
	lock, err := layout.HoldLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := os.WriteFile(filepath.Join(dir, "vmm.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, _, err := planManifestApply(name, desired, false)
	if err != nil || plan != manifestUnchanged {
		t.Fatalf("matching running plan = %v, error=%v", plan, err)
	}
	plan, _, err = planManifestApply(name, &config.ManifestProvenance{APIVersion: desired.APIVersion, Digest: "sha256:changed"}, false)
	if err != nil || plan != manifestRestart {
		t.Fatalf("changed running plan = %v, error=%v", plan, err)
	}
}
