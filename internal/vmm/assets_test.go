package vmm

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// kernelNames mirrors DefaultKernelImage's per-arch asset names.
func kernelNames() (gantry, nerdbox string) {
	if runtime.GOARCH == "amd64" {
		return "gantry-kernel-x86_64", "nerdbox-kernel-x86_64"
	}
	return "gantry-kernel-arm64", "nerdbox-kernel-arm64"
}

func TestDefaultKernelImagePreference(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GANTRY_ARTIFACTS", dir)
	gantry, nerdbox := kernelNames()

	// nothing staged: the gantry-kernel path wins (it is the download target)
	if got := DefaultKernelImage(); filepath.Base(got) != gantry {
		t.Errorf("empty artifacts: got %s, want .../%s", got, gantry)
	}
	// nerdbox staged only: fall back to it
	if err := os.WriteFile(filepath.Join(dir, nerdbox), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DefaultKernelImage(); filepath.Base(got) != nerdbox {
		t.Errorf("nerdbox staged: got %s, want .../%s", got, nerdbox)
	}
	// both staged: gantry's own hardened kernel wins
	if err := os.WriteFile(filepath.Join(dir, gantry), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DefaultKernelImage(); filepath.Base(got) != gantry {
		t.Errorf("both staged: got %s, want .../%s", got, gantry)
	}
}

func TestEnsureKernelExisting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gantry-kernel-arm64")
	if err := os.WriteFile(p, []byte("staged"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := EnsureKernel(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != p {
		t.Errorf("got %q, want %q", got, p)
	}
	if b, _ := os.ReadFile(p); string(b) != "staged" {
		t.Error("existing kernel was modified")
	}
}

func TestEnsureKernelRefusesNonGantryPath(t *testing.T) {
	if _, err := EnsureKernel(filepath.Join(t.TempDir(), "nerdbox-kernel-arm64"), nil); err == nil {
		t.Fatal("missing nerdbox asset: want error, got nil")
	}
}

func TestEnsureRootfsRefusesNonReleasePath(t *testing.T) {
	// custom names are not release assets; the gVisor variant now is
	for _, name := range []string{"my-rootfs.erofs", "nerdbox-rootfs-riscv64.erofs"} {
		if _, err := EnsureRootfs(filepath.Join(t.TempDir(), name), nil); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

// assetServer serves name with payload plus its <name>.sha256 sidecar.
func assetServer(t *testing.T, name, payload string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch path.Base(r.URL.Path) {
		case name:
			io_writeString(w, payload)
		case name + ".sha256":
			sum := sha256.Sum256([]byte(payload))
			_, _ = fmt.Fprintf(w, "%x  %s\n", sum, name)
		default:
			http.Error(w, "nope", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEnsureRootfsDownload(t *testing.T) {
	payload := strings.Repeat("R", 1<<20)
	t.Setenv("GANTRY_RELEASE_BASE", assetServer(t, "nerdbox-rootfs-arm64.erofs", payload).URL)

	dir := t.TempDir()
	dest := filepath.Join(dir, "nerdbox-rootfs-arm64.erofs")
	got, err := EnsureRootfs(dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != dest {
		t.Errorf("got %q, want %q", got, dest)
	}
	if b, _ := os.ReadFile(dest); string(b) != payload {
		t.Errorf("downloaded %d bytes, want %d", len(b), len(payload))
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("artifacts dir holds %d entries, want 1", len(entries))
	}
}

func TestEnsureKernelDownload(t *testing.T) {
	payload := strings.Repeat("K", 1<<20)
	t.Setenv("GANTRY_RELEASE_BASE", assetServer(t, "gantry-kernel-arm64", payload).URL)

	dir := t.TempDir()
	dest := filepath.Join(dir, "gantry-kernel-arm64")
	var msgs []string
	got, err := EnsureKernel(dest, func(format string, a ...any) {
		msgs = append(msgs, format)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != dest {
		t.Errorf("got %q, want %q", got, dest)
	}
	b, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != payload {
		t.Errorf("downloaded %d bytes, want %d", len(b), len(payload))
	}
	if len(msgs) == 0 {
		t.Error("progress callback never fired")
	}
	// no temp files left behind
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("artifacts dir holds %d entries, want 1", len(entries))
	}
}

func TestEnsureKernelDownload404(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	t.Setenv("GANTRY_RELEASE_BASE", srv.URL)
	dest := filepath.Join(t.TempDir(), "gantry-kernel-arm64")
	if _, err := EnsureKernel(dest, nil); err == nil || !strings.Contains(err.Error(), "refusing unverified download") {
		t.Fatalf("want missing-sidecar error, got %v", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Error("failed download left a file behind")
	}
}

func TestEnsureKernelDownloadHashMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch path.Base(r.URL.Path) {
		case "gantry-kernel-arm64":
			io_writeString(w, "payload")
		case "gantry-kernel-arm64.sha256":
			io_writeString(w, strings.Repeat("0", 64)+"  gantry-kernel-arm64\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("GANTRY_RELEASE_BASE", srv.URL)
	dir := t.TempDir()
	dest := filepath.Join(dir, "gantry-kernel-arm64")
	if _, err := EnsureKernel(dest, nil); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("want sha256 mismatch, got %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("mismatched download left %d entries behind", len(entries))
	}
}

func TestEnsureKernelDownloadOversized(t *testing.T) {
	old := maxAssetSize
	maxAssetSize = 8
	defer func() { maxAssetSize = old }()
	t.Setenv("GANTRY_RELEASE_BASE", assetServer(t, "gantry-kernel-arm64", strings.Repeat("K", 64)).URL)
	// the sidecar matches the payload, so only the size cap can trip
	dest := filepath.Join(t.TempDir(), "gantry-kernel-arm64")
	if _, err := EnsureKernel(dest, nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want oversized error, got %v", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Error("oversized download left a file behind")
	}
}

func TestReleaseBaseVersionPinned(t *testing.T) {
	old := Version
	defer func() { Version = old }()
	t.Setenv("GANTRY_RELEASE_BASE", "")
	Version = "v1.2.3"
	if got := releaseBase(); got != "https://github.com/ejpir/gantry/releases/download/v1.2.3" {
		t.Errorf("pinned releaseBase = %s", got)
	}
	Version = "dev"
	if got := releaseBase(); got != "https://github.com/ejpir/gantry/releases/latest/download" {
		t.Errorf("dev releaseBase = %s", got)
	}
}

func TestDefaultCmdlineHardening(t *testing.T) {
	cmd := DefaultCmdline("arm64", "/x/rootfs.erofs", "", 3, "", [6]byte{}, false)
	for _, want := range []string{
		"init_on_alloc=1", "init_on_free=1",
		"sysctl.kernel.kptr_restrict=2", "sysctl.kernel.dmesg_restrict=1",
		"sysctl.kernel.unprivileged_bpf_disabled=1",
		"sysctl.kernel.yama.ptrace_scope=1",
		"sysctl.net.core.bpf_jit_harden=2",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("production cmdline lacks %q:\n%s", want, cmd)
		}
	}
	// kexec stays out of the cmdline: both supported kernels compile it
	// out, so the sysctl would only printk "parameter not found"
	if strings.Contains(cmd, "kexec") {
		t.Errorf("cmdline carries kexec sysctl noise:\n%s", cmd)
	}
	// GANTRY_NO_CMDLINE_HARDENING drops the set (bisect knob)
	t.Setenv("GANTRY_NO_CMDLINE_HARDENING", "1")
	if off := DefaultCmdline("arm64", "/x/rootfs.erofs", "", 3, "", [6]byte{}, false); strings.Contains(off, "sysctl.") || strings.Contains(off, "init_on_") {
		t.Errorf("GANTRY_NO_CMDLINE_HARDENING cmdline still hardened:\n%s", off)
	}
	// debug boots (initrd combo / bare kernel) stay pristine
	if dbg := DefaultCmdline("arm64", "/x/rootfs.erofs", "/x/initrd", 3, "", [6]byte{}, false); strings.Contains(dbg, "sysctl.") {
		t.Errorf("debug cmdline carries hardening sysctls:\n%s", dbg)
	}
}

func io_writeString(w http.ResponseWriter, s string) { _, _ = w.Write([]byte(s)) }

func TestEnsureRootfsDownloadsGvisorVariant(t *testing.T) {
	payload := strings.Repeat("G", 1<<20)
	t.Setenv("GANTRY_RELEASE_BASE", assetServer(t, "nerdbox-rootfs-gvisor-arm64.erofs", payload).URL)

	dir := t.TempDir()
	dest := filepath.Join(dir, "nerdbox-rootfs-gvisor-arm64.erofs")
	if _, err := EnsureRootfs(dest, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != payload {
		t.Errorf("downloaded %d bytes, want %d", len(b), len(payload))
	}
}
