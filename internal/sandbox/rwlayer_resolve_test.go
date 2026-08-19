package sandbox

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/rwlayer"
)

func TestResolveReadOnlySkipsPerSandboxRWLayer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GANTRY_HOME", filepath.Join(home, "sandboxes"))
	dir := t.TempDir()
	t.Chdir(dir)
	for _, f := range resolveAssets {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	rf := config.RegisterRunFlags(fs)
	rf.Name = "read-only"
	if err := fs.Parse([]string{"-rw=false"}); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := Resolve(rf, fs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RW || cfg.RWLayer != "" {
		t.Fatalf("explicit read-only resolution produced RW=%v layer=%q", cfg.RW, cfg.RWLayer)
	}
	if gutil.FileExists(rwlayer.Path(rf.Name)) {
		t.Fatal("explicit read-only resolution created an unused per-sandbox rwlayer")
	}
}

func TestResolveUsesExplicitLayerForReadOnlySandbox(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GANTRY_HOME", filepath.Join(home, "sandboxes"))
	dir := t.TempDir()
	t.Chdir(dir)
	for _, f := range resolveAssets {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	layer := filepath.Join(dir, "kept.ext4")
	if err := os.WriteFile(layer, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	rf := config.RegisterRunFlags(fs)
	rf.Name = "read-only-explicit"
	if err := fs.Parse([]string{"-rw=false", "-rwlayer", layer}); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := Resolve(rf, fs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RW || cfg.RWLayer != layer {
		t.Fatalf("explicit read-only layer resolved to RW=%v layer=%q, want false/%q", cfg.RW, cfg.RWLayer, layer)
	}
}

func TestResolveUsesPerSandboxRWLayer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GANTRY_HOME", filepath.Join(home, "sandboxes"))
	dir := t.TempDir()
	t.Chdir(dir)
	for _, f := range resolveAssets {
		_ = os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644)
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	rf := config.RegisterRunFlags(fs)
	rf.Name = "dev9"
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := Resolve(rf, fs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg.RWLayer, filepath.Join("rwlayers", "dev9.ext4")) {
		t.Errorf("RWLayer = %q, want per-sandbox default", cfg.RWLayer)
	}
	if !cfg.RW {
		t.Error("RW should default on with the per-sandbox layer present")
	}
}
