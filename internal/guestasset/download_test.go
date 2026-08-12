package guestasset

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureExisting(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "gantry-kernel-arm64")
	if err := os.WriteFile(dest, []byte("staged"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := EnsureKernel(dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != dest {
		t.Errorf("got %q, want %q", got, dest)
	}
	if body, err := os.ReadFile(dest); err != nil || string(body) != "staged" {
		t.Fatalf("existing artifact changed: body=%q err=%v", body, err)
	}
}

func TestEnsureRejectsUnknownReleaseAssets(t *testing.T) {
	tests := []struct {
		name   string
		ensure func(string, func(string, ...any)) (string, error)
	}{
		{"nerdbox-kernel-arm64", EnsureKernel},
		{"gantry-kernel-riscv64", EnsureKernel},
		{"my-rootfs.erofs", EnsureRootfs},
		{"nerdbox-rootfs-riscv64.erofs", EnsureRootfs},
		{"gantry-default-image-riscv64.erofs", EnsureImage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.ensure(filepath.Join(t.TempDir(), test.name), nil); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

func TestEnsureRejectsAssetOfWrongKind(t *testing.T) {
	dir := t.TempDir()
	if _, err := EnsureKernel(filepath.Join(dir, "nerdbox-rootfs-arm64.erofs"), nil); err == nil {
		t.Fatal("rootfs accepted as a downloadable kernel")
	}
	if _, err := EnsureRootfs(filepath.Join(dir, "gantry-kernel-arm64"), nil); err == nil {
		t.Fatal("kernel accepted as a downloadable rootfs")
	}
	if _, err := EnsureImage(filepath.Join(dir, "nerdbox-rootfs-arm64.erofs"), nil); err == nil {
		t.Fatal("rootfs accepted as a downloadable default image")
	}
}

func TestEnsureRootfsDownload(t *testing.T) {
	payload := strings.Repeat("R", 1<<20)
	server := newAssetServer(t, "nerdbox-rootfs-arm64.erofs", payload)
	t.Setenv("GANTRY_RELEASE_BASE", server.URL)

	dir := t.TempDir()
	dest := filepath.Join(dir, "nerdbox-rootfs-arm64.erofs")
	got, err := EnsureRootfs(dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != dest {
		t.Errorf("got %q, want %q", got, dest)
	}
	if body, err := os.ReadFile(dest); err != nil || string(body) != payload {
		t.Fatalf("downloaded %d bytes, want %d (err=%v)", len(body), len(payload), err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("artifacts entries=%d err=%v, want 1", len(entries), err)
	}
}

func TestEnsureKernelDownloadReportsProgress(t *testing.T) {
	payload := strings.Repeat("K", 1<<20)
	server := newAssetServer(t, "gantry-kernel-arm64", payload)
	t.Setenv("GANTRY_RELEASE_BASE", server.URL)

	dir := t.TempDir()
	dest := filepath.Join(dir, "gantry-kernel-arm64")
	var messages []string
	got, err := EnsureKernel(dest, func(format string, values ...any) {
		messages = append(messages, fmt.Sprintf(format, values...))
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != dest {
		t.Errorf("got %q, want %q", got, dest)
	}
	if body, err := os.ReadFile(dest); err != nil || string(body) != payload {
		t.Fatalf("downloaded %d bytes, want %d (err=%v)", len(body), len(payload), err)
	}
	if len(messages) < 3 {
		t.Errorf("progress messages = %d, want at least start, byte progress, and staged", len(messages))
	}
	if joined := strings.Join(messages, "\n"); !strings.Contains(joined, "[====================] 100%") {
		t.Errorf("progress does not include completed bar:\n%s", joined)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("artifacts entries=%d err=%v, want 1", len(entries), err)
	}
}

func TestTaggedReleaseDownloadsIntoVersionedUserCache(t *testing.T) {
	oldVersion, oldCache, oldHome, oldTemp := Version, userCacheDir, userHomeDir, systemTempDir
	t.Cleanup(func() {
		Version, userCacheDir, userHomeDir, systemTempDir = oldVersion, oldCache, oldHome, oldTemp
	})
	payload := strings.Repeat("K", 1<<20)
	server := newAssetServer(t, "gantry-kernel-arm64", payload)
	t.Setenv("GANTRY_RELEASE_BASE", server.URL)
	t.Setenv("GANTRY_ARTIFACTS", "")
	Version = "v9.8.7"
	cache := t.TempDir()
	userCacheDir = func() (string, error) { return cache, nil }
	userHomeDir = func() (string, error) { return "", os.ErrNotExist }

	dest := releaseAssetPath("gantry-kernel-arm64")
	want := filepath.Join(cache, "gantry", "assets", Version, "gantry-kernel-arm64")
	if dest != want {
		t.Fatalf("release asset destination = %q, want %q", dest, want)
	}
	got, err := EnsureKernel(dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("EnsureKernel = %q, want %q", got, want)
	}
	if body, err := os.ReadFile(want); err != nil || string(body) != payload {
		t.Fatalf("cached release asset has %d bytes, want %d (err=%v)", len(body), len(payload), err)
	}
}

func TestEnsureRejectsMissingChecksum(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	t.Setenv("GANTRY_RELEASE_BASE", server.URL)
	dest := filepath.Join(t.TempDir(), "gantry-kernel-arm64")
	if _, err := EnsureKernel(dest, nil); err == nil || !strings.Contains(err.Error(), "refusing unverified download") {
		t.Fatalf("want missing-sidecar error, got %v", err)
	}
	assertDoesNotExist(t, dest)
}

func TestEnsureRejectsChecksumMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch path.Base(request.URL.Path) {
		case "gantry-kernel-arm64":
			writeString(w, "payload")
		case "gantry-kernel-arm64.sha256":
			writeString(w, strings.Repeat("0", 64)+"  gantry-kernel-arm64\n")
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("GANTRY_RELEASE_BASE", server.URL)
	dir := t.TempDir()
	dest := filepath.Join(dir, "gantry-kernel-arm64")
	if _, err := EnsureKernel(dest, nil); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("want sha256 mismatch, got %v", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("temporary artifacts=%d err=%v, want 0", len(entries), err)
	}
}

func TestEnsureRejectsOversizedChecksumSidecar(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, ".sha256") {
			writeString(w, strings.Repeat("0", int(maxChecksumSize)+1))
			return
		}
		http.NotFound(w, request)
	}))
	t.Cleanup(server.Close)
	t.Setenv("GANTRY_RELEASE_BASE", server.URL)
	dest := filepath.Join(t.TempDir(), "gantry-kernel-arm64")
	if _, err := EnsureKernel(dest, nil); err == nil || !strings.Contains(err.Error(), "sidecar exceeds") {
		t.Fatalf("want oversized sidecar error, got %v", err)
	}
	assertDoesNotExist(t, dest)
}

func TestEnsureRejectsOversizedContentLength(t *testing.T) {
	const name = "gantry-kernel-arm64"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch path.Base(request.URL.Path) {
		case name + ".sha256":
			sum := sha256.Sum256(nil)
			_, _ = fmt.Fprintf(w, "%x  %s\n", sum, name)
		case name:
			w.Header().Set("Content-Length", fmt.Sprint(maxAssetSize+1))
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("GANTRY_RELEASE_BASE", server.URL)
	dest := filepath.Join(t.TempDir(), name)
	if _, err := EnsureKernel(dest, nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want oversized error, got %v", err)
	}
	assertDoesNotExist(t, dest)
}

func TestCopyVerifiedEnforcesStreamingLimit(t *testing.T) {
	payload := []byte("ninebytes")
	sum := fmt.Sprintf("%x", sha256.Sum256(payload))
	if err := copyVerified(&bytes.Buffer{}, bytes.NewReader(payload), sum, int64(len(payload)-1)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want streaming size error, got %v", err)
	}
}

func TestEnsureRootfsDownloadsGVisorVariant(t *testing.T) {
	payload := strings.Repeat("G", 1<<20)
	server := newAssetServer(t, "nerdbox-rootfs-gvisor-arm64.erofs", payload)
	t.Setenv("GANTRY_RELEASE_BASE", server.URL)

	dest := filepath.Join(t.TempDir(), "nerdbox-rootfs-gvisor-arm64.erofs")
	if _, err := EnsureRootfs(dest, nil); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(dest); err != nil || string(body) != payload {
		t.Fatalf("downloaded %d bytes, want %d (err=%v)", len(body), len(payload), err)
	}
}

func TestEnsureDefaultImageDownload(t *testing.T) {
	payload := strings.Repeat("I", 1<<20)
	server := newAssetServer(t, "gantry-default-image-arm64.erofs", payload)
	t.Setenv("GANTRY_RELEASE_BASE", server.URL)

	dest := filepath.Join(t.TempDir(), "gantry-default-image-arm64.erofs")
	if _, err := EnsureImage(dest, nil); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(dest); err != nil || string(body) != payload {
		t.Fatalf("downloaded %d bytes, want %d (err=%v)", len(body), len(payload), err)
	}
}

func TestReleaseBaseUsesVersion(t *testing.T) {
	oldVersion := Version
	t.Cleanup(func() { Version = oldVersion })
	t.Setenv("GANTRY_RELEASE_BASE", "")
	Version = "v1.2.3"
	if got, want := releaseBase(), "https://github.com/ejpir/gantry/releases/download/v1.2.3"; got != want {
		t.Errorf("releaseBase = %q, want %q", got, want)
	}
	Version = "dev"
	if got, want := releaseBase(), "https://github.com/ejpir/gantry/releases/latest/download"; got != want {
		t.Errorf("releaseBase = %q, want %q", got, want)
	}
}

func newAssetServer(t *testing.T, name, payload string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch path.Base(request.URL.Path) {
		case name:
			writeString(w, payload)
		case name + ".sha256":
			sum := sha256.Sum256([]byte(payload))
			_, _ = fmt.Fprintf(w, "%x  %s\n", sum, name)
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func assertDoesNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("%s exists after failed download (stat error %v)", path, err)
	}
}

func writeString(w http.ResponseWriter, value string) {
	_, _ = w.Write([]byte(value))
}
