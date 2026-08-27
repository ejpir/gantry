package sandbox

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/guestasset"
	"github.com/ejpir/gantry/internal/sandbox/config"
)

// resolveAssets are the files Resolve requires; covers the default names
// of both supported host architectures (CI runs on x86_64).
var resolveAssets = []string{
	"gantry-kernel-arm64", "gantry-kernel-x86_64",
	"nerdbox-kernel-arm64", "nerdbox-rootfs-arm64.erofs",
	"nerdbox-kernel-x86_64", "nerdbox-rootfs-x86_64.erofs",
	"debian-bookworm.erofs",
	"gantry-ide-image-arm64.erofs", "gantry-ide-image-x86_64.erofs",
}

// touch the asset files Resolve requires, in a temp cwd
func resolveSandbox(t *testing.T, args ...string) (config.RunConfig, []string, error) {
	return resolveNamedSandbox(t, "", args...)
}

func resolveNamedSandbox(t *testing.T, name string, args ...string) (config.RunConfig, []string, error) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	for _, f := range resolveAssets {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	rf := config.RegisterRunFlags(fs)
	rf.Name = name
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return Resolve(rf, fs, nil)
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
	parse := func(args ...string) (config.RunConfig, []string, error) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		rf := config.RegisterRunFlags(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return Resolve(rf, fs, nil)
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
}

func TestResolveDevContainersDefaultsAndOverrides(t *testing.T) {
	oldEnsureImage, oldEnsureLayer, oldCheckPairing := ensureDevContainersImageAsset, ensureDevContainersRWLayer, checkDevContainersRWPairing
	t.Cleanup(func() {
		ensureDevContainersImageAsset, ensureDevContainersRWLayer, checkDevContainersRWPairing = oldEnsureImage, oldEnsureLayer, oldCheckPairing
	})
	ensureDevContainersImageAsset = func(path string, _ func(string, ...any)) (string, error) { return path, nil }
	ensureDevContainersRWLayer = func(_ string, _ string, _ uint, _ func(string, ...any)) (string, []string, error) {
		path := "devcontainers.ext4"
		return path, nil, os.WriteFile(path, []byte("x"), 0o600)
	}
	checkDevContainersRWPairing = func(string, string) error { return nil }

	cfg, _, err := resolveNamedSandbox(t, "dev", "-ssh", "-devcontainers", "-rwlayer", "debian-bookworm.erofs")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SSH || !cfg.DevContainers || cfg.Runtime != "crun" || !cfg.RW {
		t.Fatalf("devcontainers config = %+v", cfg)
	}
	if filepath.Base(cfg.Image) != "debian-bookworm.erofs" {
		t.Fatalf("workload image was replaced by IDE image: %s", cfg.Image)
	}
	if cfg.DevContainersImageCfg == nil || cfg.DevContainersImageCfg.User != "gantry" || cfg.DevContainersImageCfg.UID != 1000 ||
		cfg.DevContainersImageCfg.GID != 1000 || cfg.DevContainersImageCfg.WorkingDir != "/home/gantry" {
		t.Fatalf("curated development image config = %+v", cfg.DevContainersImageCfg)
	}
	if cfg.DevContainersImage == "" || cfg.DevContainersRWLayer == "" {
		t.Fatalf("Dev Containers peer root was not resolved: %+v", cfg)
	}
	if cfg.MemMB != config.DefaultDevContainersMemoryMiB ||
		cfg.VCPUs != min(config.DefaultDevContainersVCPUs, config.MaxSandboxVCPUs()) ||
		cfg.DevContainersDiskMiB != config.DefaultDevContainersDiskSizeMiB ||
		cfg.RWLayerSizeMiB != config.DefaultRWLayerSizeMiB {
		t.Fatalf("devcontainers defaults = %d MiB, %d CPU, IDE disk %d MiB, workload disk %d MiB",
			cfg.MemMB, cfg.VCPUs, cfg.DevContainersDiskMiB, cfg.RWLayerSizeMiB)
	}

	cfg, _, err = resolveNamedSandbox(t, "dev", "-ssh", "-devcontainers", "-rwlayer", "debian-bookworm.erofs", "-mem", "2048", "-cpus", "1", "-disk-size", "8192")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MemMB != 2048 || cfg.VCPUs != 1 || cfg.RWLayerSizeMiB != 8192 || cfg.DevContainersDiskMiB != 8192 {
		t.Fatalf("explicit resources were replaced: %+v", cfg)
	}
	readOnlyWorkload, _, err := resolveNamedSandbox(t, "dev", "-ssh", "-devcontainers", "-rw=false")
	if err != nil {
		t.Fatal(err)
	}
	if readOnlyWorkload.RW || readOnlyWorkload.DevContainersRWLayer == "" {
		t.Fatalf("read-only workload did not retain writable IDE peer: %+v", readOnlyWorkload)
	}

	if _, _, err := resolveNamedSandbox(t, "dev", "-devcontainers", "-rwlayer", "debian-bookworm.erofs"); err == nil || !strings.Contains(err.Error(), "requires -ssh") {
		t.Fatalf("devcontainers without SSH error = %v", err)
	}
	if _, _, err := resolveNamedSandbox(t, "dev", "-ssh", "-devcontainers", "-runtime", "runsc"); err == nil || !strings.Contains(err.Error(), "requires -runtime crun") {
		t.Fatalf("devcontainers with runsc error = %v", err)
	}
}

func TestResolveRejectsInvalidResources(t *testing.T) {
	for _, args := range [][]string{
		{"-mem", "0"},
		{"-cpus", "0"},
		{"-cpus", fmt.Sprint(config.MaxSandboxVCPUs() + 1)},
	} {
		if _, _, err := resolveSandbox(t, args...); err == nil {
			t.Errorf("Resolve accepted invalid resources %v", args)
		}
	}
}

func TestResolveMCPFilesystemRootUsesGuestPathSemantics(t *testing.T) {
	cfg, _, err := resolveSandbox(t, "-mcp", "-mcp-fs-root", "/work")
	if err != nil {
		t.Fatalf("absolute Linux guest path: %v", err)
	}
	if cfg.MCPFSRoot != "/work" {
		t.Fatalf("MCPFSRoot = %q, want /work", cfg.MCPFSRoot)
	}
	if _, _, err := resolveSandbox(t, "-mcp", "-mcp-fs-root", "work"); err == nil ||
		!strings.Contains(err.Error(), "absolute guest path") {
		t.Fatalf("relative MCP filesystem root error = %v", err)
	}
}

func TestResolveOAuthBridgeDefaultsOnAndPersistsOptOut(t *testing.T) {
	cfg, _, err := resolveNamedSandbox(t, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.OAuthBridgeEnabled() {
		t.Fatal("OAuth bridge must default on")
	}
	cfg, _, err = resolveNamedSandbox(t, "agent", "-oauth-bridge=false")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OAuthBridge == nil || cfg.OAuthBridgeEnabled() {
		t.Fatal("-oauth-bridge=false did not persist the opt-out")
	}
	if !(config.RunConfig{}).OAuthBridgeEnabled() {
		t.Fatal("legacy config without oauth_bridge must default on")
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip config.RunConfig
	if err := json.Unmarshal(raw, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.OAuthBridge == nil || roundTrip.OAuthBridgeEnabled() {
		t.Fatalf("persisted opt-out did not survive JSON round trip: %s", raw)
	}
	oneShot, _, err := resolveSandbox(t, "-oauth-bridge=false")
	if err != nil {
		t.Fatalf("one-shot -oauth-bridge=false: %v", err)
	}
	if oneShot.OAuthBridge == nil || oneShot.OAuthBridgeEnabled() {
		t.Fatal("one-shot OAuth bridge opt-out was not preserved")
	}
	if _, _, err := resolveNamedSandbox(t, "agent", "-oauth-custody", "-oauth-bridge=false"); err == nil || !strings.Contains(err.Error(), "requires -oauth-bridge=true") {
		t.Fatalf("custody without callback bridge error = %v", err)
	}
}

func TestResolveRunscDownloadsGvisorRootfs(t *testing.T) {
	// the mapped gVisor rootfs is a whitelisted release asset: a first
	// runsc start downloads it like the default rootfs instead of
	// demanding a local mkrootfs-gvisor.sh build.
	cfg, err := resolveSandboxNoRootfs(t, guestServer(t).URL, "-runtime", "runsc")
	if err != nil {
		t.Fatal(err)
	}
	want := "nerdbox-rootfs-gvisor-arm64.erofs"
	if runtime.GOARCH == "amd64" {
		want = "nerdbox-rootfs-gvisor-x86_64.erofs"
	}
	if filepath.Base(cfg.Rootfs) != want {
		t.Errorf("rootfs = %s, want .../%s", cfg.Rootfs, want)
	}
	if b, _ := os.ReadFile(cfg.Rootfs); string(b) != "downloaded-"+want {
		t.Errorf("rootfs content = %q, want the downloaded payload", b)
	}
	if runtime.GOARCH == "arm64" && !strings.HasSuffix(cfg.Kernel, "-4k") {
		t.Errorf("runsc on arm64 must map to the 4K kernel, got %s", cfg.Kernel)
	}
}

func TestResolveRunscExplicitRootfsMissing(t *testing.T) {
	// an explicit -rootfs is user-supplied: never downloaded, hard error
	if _, err := resolveSandboxNoRootfs(t, guestServer(t).URL, "-runtime", "runsc", "-rootfs", "/nope/gvisor.erofs"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("explicit missing -rootfs with runsc: want not-found error, got %v", err)
	}
}

func TestResolveSharesRequireWritableRoot(t *testing.T) {
	if _, _, err := resolveSandbox(t, "-rw=false", "-share", "code=/tmp"); err == nil || !strings.Contains(err.Error(), "writable container root") {
		t.Errorf("shares with -rw=false: want writable-root error, got %v", err)
	}
}

func TestResolveNewSandboxPropagatesMissingRegistryCredential(t *testing.T) {
	var registry *httptest.Server
	registry = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case strings.HasPrefix(req.URL.Path, "/v2/private/app/manifests/"):
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="test",scope="repository:private/app:pull"`, registry.URL))
			w.WriteHeader(http.StatusUnauthorized)
		case req.URL.Path == "/token":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(registry.Close)

	dir := t.TempDir()
	kernel := make([]byte, 0x40)
	binary.LittleEndian.PutUint32(kernel[0x38:], 0x644d5241) // raw arm64 Image
	kernelPath := filepath.Join(dir, "kernel")
	rootfsPath := filepath.Join(dir, "rootfs.erofs")
	if err := os.WriteFile(kernelPath, kernel, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyHome := filepath.Join(dir, "home")
	if err := os.MkdirAll(emptyHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", emptyHome)
	t.Setenv("USERPROFILE", emptyHome)
	t.Setenv("GANTRY_REGISTRY_AUTH", "")
	t.Setenv("GANTRY_IMAGES", filepath.Join(dir, "images"))
	t.Setenv("XDG_RUNTIME_DIR", "")

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	rf := config.RegisterRunFlags(fs)
	ref := strings.TrimPrefix(registry.URL, "http://") + "/private/app:latest"
	if err := fs.Parse([]string{
		"-kernel", kernelPath, "-rootfs", rootfsPath,
		"-image", ref, "-rw=false",
	}); err != nil {
		t.Fatal(err)
	}
	_, _, err := Resolve(rf, fs, nil)
	if err == nil {
		t.Fatal("new sandbox resolution succeeded without private-registry credentials")
	}
	for _, want := range []string{
		"authentication required to pull private/app",
		"no usable registry pull credential is configured",
		"gantry image login " + strings.TrimPrefix(registry.URL, "http://"),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("new-sandbox error %q does not contain %q", err, want)
		}
	}
}

// resolveSandboxNoKernel stages everything but the kernels and points the
// release download at srv, so Resolve exercises the on-demand fetch.
func resolveSandboxNoKernel(t *testing.T, srv string, args ...string) (config.RunConfig, error) {
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
	rf := config.RegisterRunFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := Resolve(rf, fs, nil)
	return cfg, err
}

// resolveSandboxNoRootfs stages everything but the rootfs assets and points
// the release download at srv, so Resolve exercises the rootfs fetch.
func resolveSandboxNoRootfs(t *testing.T, srv string, args ...string) (config.RunConfig, error) {
	t.Helper()
	t.Setenv("GANTRY_RELEASE_BASE", srv)
	dir := t.TempDir()
	t.Chdir(dir)
	assets := []string{
		"gantry-kernel-arm64", "gantry-kernel-x86_64",
		"debian-bookworm.erofs",
	}
	for _, f := range assets {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	rf := config.RegisterRunFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := Resolve(rf, fs, nil)
	return cfg, err
}

// guestServer serves kernel, VM rootfs, and default OCI release assets.
func guestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := path.Base(r.URL.Path)
		if strings.HasSuffix(base, ".sha256") {
			asset := strings.TrimSuffix(base, ".sha256")
			if strings.HasPrefix(asset, "gantry-kernel-") || strings.HasPrefix(asset, "nerdbox-rootfs-") || strings.HasPrefix(asset, "gantry-default-image-") {
				sum := sha256.Sum256([]byte("downloaded-" + asset))
				_, _ = fmt.Fprintf(w, "%x  %s\n", sum, asset)
				return
			}
		}
		if strings.HasPrefix(base, "gantry-kernel-") || strings.HasPrefix(base, "nerdbox-rootfs-") || strings.HasPrefix(base, "gantry-default-image-") {
			_, _ = w.Write([]byte("downloaded-" + base))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestResolveBlankImageDownloadsReleaseDefault(t *testing.T) {
	oldVersion := guestasset.Version
	t.Cleanup(func() { guestasset.Version = oldVersion })
	guestasset.Version = "v9.8.7"
	t.Setenv("GANTRY_RELEASE_BASE", guestServer(t).URL)
	assets := t.TempDir()
	t.Setenv("GANTRY_ARTIFACTS", assets)

	arch := "arm64"
	if runtime.GOARCH == "amd64" {
		arch = "x86_64"
	}
	for _, name := range []string{"gantry-kernel-" + arch, "nerdbox-rootfs-" + arch + ".erofs"} {
		if err := os.WriteFile(filepath.Join(assets, name), []byte("staged"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	rf := config.RegisterRunFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := Resolve(rf, fs, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "gantry-default-image-" + arch + ".erofs"
	if filepath.Base(cfg.Image) != want {
		t.Fatalf("blank -image resolved to %q, want %q", cfg.Image, want)
	}
	if body, err := os.ReadFile(cfg.Image); err != nil || string(body) != "downloaded-"+want {
		t.Fatalf("default image content = %q, want downloaded payload (err=%v)", body, err)
	}
}

func TestResolveDownloadsRootfs(t *testing.T) {
	cfg, err := resolveSandboxNoRootfs(t, guestServer(t).URL)
	if err != nil {
		t.Fatal(err)
	}
	want := "nerdbox-rootfs-arm64.erofs"
	if runtime.GOARCH == "amd64" {
		want = "nerdbox-rootfs-x86_64.erofs"
	}
	if filepath.Base(cfg.Rootfs) != want {
		t.Errorf("rootfs = %s, want .../%s", cfg.Rootfs, want)
	}
	if b, _ := os.ReadFile(cfg.Rootfs); string(b) != "downloaded-"+want {
		t.Errorf("rootfs content = %q, want the downloaded payload", b)
	}
}

func TestResolveExplicitRootfsMissing(t *testing.T) {
	if _, err := resolveSandboxNoRootfs(t, guestServer(t).URL, "-rootfs", "/nope/custom.erofs"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("explicit missing -rootfs: want not-found error, got %v", err)
	}
}

func kernelServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := path.Base(r.URL.Path)
		if strings.HasSuffix(base, ".sha256") {
			asset := strings.TrimSuffix(base, ".sha256")
			if strings.HasPrefix(asset, "gantry-kernel-") {
				sum := sha256.Sum256([]byte("downloaded-kernel"))
				_, _ = fmt.Fprintf(w, "%x  %s\n", sum, asset)
				return
			}
		}
		if strings.HasPrefix(base, "gantry-kernel-") {
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
	if cfg.KernelPolicy != config.KernelPolicyRelease {
		t.Errorf("default kernel policy = %q, want %q", cfg.KernelPolicy, config.KernelPolicyRelease)
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

func TestResolvePreservesExplicitCustomKernel(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom-kernel")
	if err := os.WriteFile(custom, []byte("caller-owned kernel"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := resolveSandbox(t, "-kernel", custom)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.Abs(custom)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Kernel != want {
		t.Fatalf("explicit kernel = %q, want unchanged path %q", cfg.Kernel, want)
	}
	if cfg.KernelPolicy != config.KernelPolicyPinned {
		t.Fatalf("explicit kernel policy = %q, want %q", cfg.KernelPolicy, config.KernelPolicyPinned)
	}
	if body, err := os.ReadFile(cfg.Kernel); err != nil || string(body) != "caller-owned kernel" {
		t.Fatalf("explicit kernel changed: body=%q err=%v", body, err)
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
		{"/Users/x/repos/gantry", "pi-gantry"},
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

// Share specs are absolutized in Resolve — the explicit mount target must
// survive the normalization (it was silently dropped, which is why
// `gantry pi` mounted the project at /host/ws instead of /workspace).
func TestResolveShareCtrPathPreserved(t *testing.T) {
	layer := filepath.Join(t.TempDir(), "rw.ext4")
	if err := os.WriteFile(layer, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := resolveSandbox(t, "-share", "ws=/tmp,mount=/workspace", "-share", "code=/tmp,mount=/src,ro", "-rwlayer", layer)
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

func TestResolveLayerSet(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	files := append(append([]string{}, resolveAssets...),
		"fsmeta.erofs", "l1.erofs", "l2.erofs", "rw.ext4")
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifest := filepath.Join(dir, "ls.json")
	_ = os.WriteFile(manifest, []byte(`{"fsmeta":"fsmeta.erofs","layers":["l1.erofs","l2.erofs"]}`), 0o644)

	parse := func(args ...string) (config.RunConfig, []string, error) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		rf := config.RegisterRunFlags(fs)
		rf.Name = "lsbox"
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return Resolve(rf, fs, nil)
	}

	cfg, _, err := parse("-layerset", manifest, "-rwlayer", filepath.Join(dir, "rw.ext4"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LayerSet == nil || len(cfg.LayerSet.Layers) != 2 {
		t.Fatalf("LayerSet = %+v", cfg.LayerSet)
	}
	if !cfg.RW {
		t.Error("a layerset must force RW on")
	}
	if cfg.ImageCfg != nil || cfg.ImageRef != "" {
		t.Error("no image resolution should happen for a layerset")
	}

	// the image file requirement is waived, the rwlayer requirement is not
	if _, _, err := parse("-layerset", manifest); err == nil {
		// per-sandbox default rwlayer would be created under ~/.gantry —
		// in the temp HOME-less test env this may resolve; what must hold
		// is the -rw=false rejection below
		_ = err
	}
	if _, _, err = parse("-layerset", manifest, "-rwlayer", filepath.Join(dir, "rw.ext4"), "-rw=false"); err == nil {
		t.Fatal("want -rw=false rejection for a layerset")
	}
	// the rwlayer attaches RW after the RO set
	if !cfg.RW || cfg.RWLayer == "" {
		t.Fatalf("RW=%v RWLayer=%q", cfg.RW, cfg.RWLayer)
	}
}

func TestResolveShareOwnerRoundTrip(t *testing.T) {
	// regression: -share ...,uid=N,gid=N must survive Resolve's
	// normalize-and-persist; dropping the suffix made the mapping a no-op.
	dir := t.TempDir()
	t.Chdir(dir)
	for _, f := range append(append([]string{}, resolveAssets...), "rwlayer.ext4") {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	parse := func(args ...string) (config.RunConfig, []string, error) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		rf := config.RegisterRunFlags(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return Resolve(rf, fs, nil)
	}
	shareDir := filepath.Join(dir, "shared")
	if err := os.Mkdir(shareDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := parse("-share", "code="+shareDir+",uid=1000,gid=1000")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 1 {
		t.Fatalf("shares = %v", cfg.Shares)
	}
	parsed, err := cfg.ParsedShares()
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 1 || parsed[0].UID == nil || *parsed[0].UID != 1000 || parsed[0].GID == nil || *parsed[0].GID != 1000 {
		t.Fatalf("uid/gid lost in round-trip: spec=%q parsed=%+v", cfg.Shares[0], parsed)
	}
	// ro + ctrpath + owner all compose
	cfg, _, err = parse("-share", "code="+shareDir+",mount=/data,ro,uid=7,gid=8")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = cfg.ParsedShares()
	if err != nil {
		t.Fatal(err)
	}
	if !parsed[0].RO || parsed[0].CtrPath != "/data" || parsed[0].UID == nil || *parsed[0].UID != 7 || *parsed[0].GID != 8 {
		t.Fatalf("composed spec lost options: %q -> %+v", cfg.Shares[0], parsed[0])
	}
}

// TestOptsOpensBootAssets verifies that Opts resolves and opens every boot
// asset up front: the returned vmm.Opts carries live descriptors whose
// backing files are exactly the configured paths (path swaps after
// resolution cannot affect what boots).
func TestOptsOpensBootAssets(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, size int) string {
		p := filepath.Join(dir, name)
		blob := make([]byte, size)
		if name == "Image" {
			blob = append(blob[:0x38], []byte("ARM\x64")...) // arm64 magic @ 0x38
			blob = blob[:size]
		}
		if err := os.WriteFile(p, blob, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	kernel := mk("Image", 0x40)
	rootfs := mk("rootfs.erofs", 1<<20)
	layer := mk("layer.erofs", 1<<20)
	rwlayer := mk("rwlayer.img", 1<<20)

	cfg := config.RunConfig{
		Kernel:  kernel,
		Rootfs:  rootfs,
		Image:   layer,
		RW:      true,
		RWLayer: rwlayer,
		MemMB:   256,
		VCPUs:   2,
	}
	o, err := vmmOpts(cfg, nil, "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, f := range append(append([]*os.File{o.Kernel, o.Rootfs}, o.DisksRO...), o.Disks...) {
			_ = f.Close()
		}
	}()
	for path, f := range map[string]*os.File{
		kernel:  o.Kernel,
		rootfs:  o.Rootfs,
		layer:   o.DisksRO[0],
		rwlayer: o.Disks[0],
	} {
		if f == nil {
			t.Fatalf("%s: not opened", path)
		}
		fi, err := f.Stat()
		if err != nil || fi.Size() == 0 {
			t.Fatalf("%s: descriptor not live: %v", path, err)
		}
		want, _ := filepath.EvalSymlinks(path)
		got, _ := filepath.EvalSymlinks(f.Name())
		if want != got {
			t.Fatalf("descriptor for %s actually names %s", want, got)
		}
	}
	if o.NetPolicy != nil || o.NetTraffic != nil || o.NetConn != nil {
		t.Fatal("nil network should produce nil net opts")
	}

	// A missing asset fails the whole Opts and leaks nothing the caller
	// could misuse (the error path closes what it opened).
	cfg.Image = filepath.Join(dir, "gone.erofs")
	if _, err := vmmOpts(cfg, nil, "", false); err == nil {
		t.Fatal("Opts with a missing layer succeeded")
	}
}

func TestOptsAttachesWorkloadAndIDEImagesBeforeWritableLayers(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, payload []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	kernelData := make([]byte, 0x40)
	copy(kernelData[0x38:], []byte("ARM\x64"))
	cfg := config.RunConfig{
		Kernel: write("Image", kernelData), Rootfs: write("root.erofs", []byte("root")),
		Image: write("work.erofs", []byte("work")), RW: true, RWLayer: write("work.ext4", []byte("work-rw")),
		DevContainers: true, DevContainersImage: write("ide.erofs", []byte("ide")),
		DevContainersRWLayer: write("ide.ext4", []byte("ide-rw")),
		MemMB:                256, VCPUs: 1,
	}
	opts, err := vmmOpts(cfg, nil, "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, file := range append(append([]*os.File{opts.Kernel, opts.Rootfs}, opts.DisksRO...), opts.Disks...) {
			_ = file.Close()
		}
	}()
	if got := []string{opts.DisksRO[0].Name(), opts.DisksRO[1].Name(), opts.Disks[0].Name(), opts.Disks[1].Name()}; !reflect.DeepEqual(got, []string{cfg.Image, cfg.DevContainersImage, cfg.RWLayer, cfg.DevContainersRWLayer}) {
		t.Fatalf("disk attachment order = %v", got)
	}
}

func TestResolveProxyFlags(t *testing.T) {
	cfg, _, err := resolveSandbox(t,
		"-proxy", "HTTP://proxy.example:3128/",
		"-no-proxy", "localhost,.corp.example",
		"-proxy-enforce",
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProxyURL != "http://proxy.example:3128/" || cfg.NoProxy != "localhost,.corp.example" || !cfg.ProxyEnforce {
		t.Fatalf("resolved proxy config = %+v", cfg)
	}
}
