package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ejpir/gantry/internal/guestasset"
)

func stageRestartKernel(t *testing.T, sandboxRuntime string) string {
	t.Helper()
	assets := t.TempDir()
	t.Setenv("GANTRY_ARTIFACTS", assets)
	kernel := guestasset.DefaultKernel()
	if sandboxRuntime == "runsc" {
		kernel = guestasset.GVisorKernel(kernel)
	}
	if err := os.WriteFile(kernel, []byte("current release kernel"), 0o644); err != nil {
		t.Fatal(err)
	}
	absolute, err := filepath.Abs(kernel)
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}

func legacyReleaseKernel(t *testing.T) string {
	t.Helper()
	name := "gantry-kernel-arm64"
	if runtime.GOARCH == "amd64" {
		name = "gantry-kernel-x86_64"
	}
	return filepath.Join(t.TempDir(), "gantry", "assets", "v0.0.7", name)
}

func TestRefreshKernelForRestartAdvancesReleaseKernel(t *testing.T) {
	want := stageRestartKernel(t, "crun")
	cfg := RunConfig{Kernel: legacyReleaseKernel(t), KernelPolicy: kernelPolicyRelease, Runtime: "crun"}
	got, changed, err := refreshKernelForRestart(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || got.Kernel != want || got.KernelPolicy != kernelPolicyRelease {
		t.Fatalf("refresh = (%+v, %v), want kernel=%q policy=%q", got, changed, want, kernelPolicyRelease)
	}
}

func TestRefreshKernelForRestartPreservesPinnedKernel(t *testing.T) {
	_ = stageRestartKernel(t, "crun")
	custom := filepath.Join(t.TempDir(), "custom-kernel")
	cfg := RunConfig{Kernel: custom, KernelPolicy: kernelPolicyPinned}
	got, changed, err := refreshKernelForRestart(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if changed || got.Kernel != custom || got.KernelPolicy != kernelPolicyPinned {
		t.Fatalf("pinned kernel changed: (%+v, %v)", got, changed)
	}
}

func TestRefreshKernelForRestartMigratesLegacyPolicies(t *testing.T) {
	want := stageRestartKernel(t, "crun")
	managed := RunConfig{Kernel: legacyReleaseKernel(t)}
	got, changed, err := refreshKernelForRestart(managed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || got.Kernel != want || got.KernelPolicy != kernelPolicyRelease {
		t.Fatalf("legacy managed refresh = (%+v, %v)", got, changed)
	}

	custom := filepath.Join(t.TempDir(), "custom-kernel")
	got, changed, err = refreshKernelForRestart(RunConfig{Kernel: custom}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || got.Kernel != custom || got.KernelPolicy != kernelPolicyPinned {
		t.Fatalf("legacy custom migration = (%+v, %v)", got, changed)
	}
}

func TestRefreshKernelForRestartSelectsRunscVariant(t *testing.T) {
	want := stageRestartKernel(t, "runsc")
	cfg := RunConfig{Kernel: legacyReleaseKernel(t), KernelPolicy: kernelPolicyRelease, Runtime: "runsc"}
	got, _, err := refreshKernelForRestart(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kernel != want {
		t.Fatalf("runsc kernel = %q, want %q", got.Kernel, want)
	}
}

func TestRefreshSavedKernelForRestartPersistsBeforeBoot(t *testing.T) {
	want := stageRestartKernel(t, "crun")
	dir := t.TempDir()
	cfg := RunConfig{Kernel: legacyReleaseKernel(t), KernelPolicy: kernelPolicyRelease}
	refreshed, changed, err := refreshSavedKernelForRestart(dir, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || refreshed.Kernel != want {
		t.Fatalf("refresh = (%+v, %v), want %q", refreshed, changed, want)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted RunConfig
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Kernel != want || persisted.KernelPolicy != kernelPolicyRelease {
		t.Fatalf("persisted config = %+v", persisted)
	}
}
