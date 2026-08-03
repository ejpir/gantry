package sandbox

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"runtime"
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

// resolveSandboxNoKernel stages everything but the kernels and points the
// release download at srv, so Resolve exercises the on-demand fetch.
func resolveSandboxNoKernel(t *testing.T, srv string, args ...string) (RunConfig, error) {
	t.Helper()
	t.Setenv("GANTRY_RELEASE_BASE", srv)
	dir := t.TempDir()
	t.Chdir(dir)
	assets := []string{
		"nerdbox-rootfs-arm64.erofs", "nerdbox-rootfs-gvisor-arm64.erofs",
		"nerdbox-rootfs-x86_64.erofs", "nerdbox-rootfs-gvisor-x86_64.erofs",
		"debian-bookworm.erofs",
	}
	for _, f := range assets {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	rf := RegisterRunFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := rf.Resolve(fs, nil)
	return cfg, err
}

func kernelServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(path.Base(r.URL.Path), "gantry-kernel-") {
			_, _ = w.Write([]byte("downloaded-kernel"))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestResolveDownloadsKernel(t *testing.T) {
	cfg, err := resolveSandboxNoKernel(t, kernelServer(t).URL)
	if err != nil {
		t.Fatal(err)
	}
	want := "gantry-kernel-arm64"
	if runtime.GOARCH == "amd64" {
		want = "gantry-kernel-x86_64"
	}
	if filepath.Base(cfg.Kernel) != want {
		t.Errorf("kernel = %s, want .../%s", cfg.Kernel, want)
	}
	if b, _ := os.ReadFile(cfg.Kernel); string(b) != "downloaded-kernel" {
		t.Errorf("kernel content = %q, want the downloaded payload", b)
	}
}

func TestResolveRunscDownloads4kKernel(t *testing.T) {
	cfg, err := resolveSandboxNoKernel(t, kernelServer(t).URL, "-runtime", "runsc")
	if err != nil {
		t.Fatal(err)
	}
	want := "gantry-kernel-arm64-4k"
	if runtime.GOARCH == "amd64" {
		want = "gantry-kernel-x86_64" // x86_64 is always 4K pages
	}
	if filepath.Base(cfg.Kernel) != want {
		t.Errorf("runsc kernel = %s, want .../%s", cfg.Kernel, want)
	}
}

func TestResolveExplicitKernelMissing(t *testing.T) {
	_, err := resolveSandboxNoKernel(t, kernelServer(t).URL, "-kernel", "/no/such/kernel")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("explicit missing kernel: want not-found error, got %v", err)
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

func TestPiSandboxName(t *testing.T) {
	for _, tc := range []struct{ cwd, want string }{
		{"/Users/x/repos/minivm", "pi-minivm"},
		{"/Users/x/repos/my project (v2)", "pi-my-project--v2-"},
		{"/", "pi--"},
	} {
		if got := piSandboxName(tc.cwd); got != tc.want {
			t.Errorf("piSandboxName(%q) = %q, want %q", tc.cwd, got, tc.want)
		}
		if err := ValidateSandboxName(piSandboxName(tc.cwd)); err != nil {
			t.Errorf("piSandboxName(%q) invalid: %v", tc.cwd, err)
		}
	}
	long := "/" + string(make([]byte, 200))
	if n := piSandboxName(long); len(n) > 64 {
		t.Errorf("name length %d > 64", len(n))
	}
}

// Share specs are absolutized in Resolve — the explicit @CTRPATH must
// survive the normalization (it was silently dropped, which is why
// `gantry pi` mounted the project at /host/ws instead of /workspace).
func TestResolveShareCtrPathPreserved(t *testing.T) {
	cfg, _, err := resolveSandbox(t, "-share", "ws=/tmp@/workspace", "-share", "code=/tmp@/src,ro")
	if err != nil {
		t.Fatal(err)
	}
	shares, err := cfg.ParsedShares()
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 2 {
		t.Fatalf("shares = %+v", shares)
	}
	if shares[0].CtrPath != "/workspace" {
		t.Errorf("ws CtrPath = %q, want /workspace", shares[0].CtrPath)
	}
	if shares[1].CtrPath != "/src" || !shares[1].RO {
		t.Errorf("code = %+v, want CtrPath=/src ro", shares[1])
	}
}
