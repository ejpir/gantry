package vmm

import (
	"net/http"
	"net/http/httptest"
	"os"
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
	// custom names and the locally built gVisor variant are not release assets
	for _, name := range []string{"my-rootfs.erofs", "nerdbox-rootfs-gvisor-arm64.erofs"} {
		if _, err := EnsureRootfs(filepath.Join(t.TempDir(), name), nil); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

func TestEnsureRootfsDownload(t *testing.T) {
	payload := strings.Repeat("R", 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/nerdbox-rootfs-arm64.erofs") {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		io_writeString(w, payload)
	}))
	defer srv.Close()
	t.Setenv("GANTRY_RELEASE_BASE", srv.URL)

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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/gantry-kernel-arm64") {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		io_writeString(w, payload)
	}))
	defer srv.Close()
	t.Setenv("GANTRY_RELEASE_BASE", srv.URL)

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
	if _, err := EnsureKernel(dest, nil); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("want 404 error, got %v", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Error("failed download left a file behind")
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
