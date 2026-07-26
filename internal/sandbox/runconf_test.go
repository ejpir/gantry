package sandbox

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resolveAssets are the files Resolve requires; covers the default names
// of both supported host architectures (CI runs on x86_64).
var resolveAssets = []string{
	"nerdbox-kernel-arm64", "nerdbox-rootfs-arm64.erofs",
	"nerdbox-kernel-x86_64", "nerdbox-rootfs-x86_64.erofs",
	"debian-bookworm.erofs",
}

// touch the asset files Resolve requires, in a temp cwd
func resolveSandbox(t *testing.T, args ...string) (RunConfig, []string, error) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	for _, f := range resolveAssets {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	rf := RegisterRunFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return rf.Resolve(fs, nil)
}

func TestResolveRWRules(t *testing.T) {
	// regression: explicit -rw with no rwlayer must not hand the guest
	// RW=true for a /dev/vdc that was never attached — degrade + warn.
	cfg, warns, err := resolveSandbox(t, "-rw")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RW {
		t.Error("-rw with no rwlayer: RW should degrade to false")
	}
	if len(warns) == 0 || !strings.Contains(warns[0], "read-only") {
		t.Errorf("-rw with no rwlayer: want a read-only warning, got %v", warns)
	}

	// default (no -rw flag) with no rwlayer: read-only, silently
	cfg, warns, err = resolveSandbox(t)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RW || len(warns) != 0 {
		t.Errorf("no flags: RW=%v warns=%v, want false/[]", cfg.RW, warns)
	}
}

func TestResolveRWWithLayer(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for _, f := range append(append([]string{}, resolveAssets...), "rwlayer.ext4") {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	parse := func(args ...string) (RunConfig, []string, error) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		rf := RegisterRunFlags(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return rf.Resolve(fs, nil)
	}

	// a rwlayer existing defaults RW on
	cfg, warns, err := parse()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RW || cfg.RWLayer == "" || len(warns) != 0 {
		t.Errorf("rwlayer present: RW=%v layer=%q warns=%v, want true/set/[]", cfg.RW, cfg.RWLayer, warns)
	}

	// explicit -rw with a layer: on, no warning
	cfg, warns, err = parse("-rw")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RW || len(warns) != 0 {
		t.Errorf("-rw with layer: RW=%v warns=%v, want true/[]", cfg.RW, warns)
	}
}

func TestResolveRuntimeSwitch(t *testing.T) {
	if _, _, err := resolveSandbox(t, "-runtime", "bogus"); err == nil || !strings.Contains(err.Error(), "crun or runsc") {
		t.Errorf("bogus runtime: want switch error, got %v", err)
	}
	// runsc without the gvisor rootfs: actionable error
	if _, _, err := resolveSandbox(t, "-runtime", "runsc"); err == nil || !strings.Contains(err.Error(), "mkrootfs-gvisor.sh") {
		t.Errorf("runsc without rootfs: want mkrootfs-gvisor hint, got %v", err)
	}
}

func TestValidateSandboxName(t *testing.T) {
	for _, ok := range []string{"dev", "a.b_c-d", "x"} {
		if err := ValidateSandboxName(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"", ".", "..", "a/b", "a b", strings.Repeat("x", 65)} {
		if err := ValidateSandboxName(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}
