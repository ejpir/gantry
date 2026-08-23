//go:build linux

package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/guestasset"
)

func TestApplyVerifiesAndReplacesExecutable(t *testing.T) {
	preserveTestGlobals(t)
	guestasset.Version = "v1.0.0"
	cachePath := filepath.Join(t.TempDir(), "cache", "update.json")
	cacheFile = func() string { return cachePath }
	target := filepath.Join(t.TempDir(), "gantry")
	if err := os.WriteFile(target, []byte("old"), 0o751); err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return target, nil }
	payload := minimalNativeBinary(t)
	sum := sha256.Sum256(payload)
	asset, err := platformAsset(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/latest":
			_, _ = writer.Write([]byte(`{"tag_name":"v1.1.0"}`))
		case "/download/v1.1.0/" + asset + ".sha256":
			_, _ = fmt.Fprintf(writer, "%s  %s\n", hex.EncodeToString(sum[:]), asset)
		case "/download/v1.1.0/" + asset:
			writer.Header().Set("Content-Length", fmt.Sprint(len(payload)))
			_, _ = writer.Write(payload)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	latestReleaseEndpoint = server.URL + "/latest"
	releaseDownloadBase = server.URL + "/download"
	httpClient = server.Client()

	var progress []string
	result, err := Apply(context.Background(), func(format string, values ...any) {
		progress = append(progress, fmt.Sprintf(format, values...))
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Previous != "v1.0.0" || result.Installed != "v1.1.0" || result.Executable != target {
		t.Fatalf("result = %+v", result)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatal("installed executable differs from verified release payload")
	}
	if info, _ := os.Stat(target); info.Mode().Perm() != 0o751 {
		t.Fatalf("installed mode = %o, want 751", info.Mode().Perm())
	}
	if !strings.Contains(strings.Join(progress, "\n"), "verified "+asset) {
		t.Fatalf("progress = %q", progress)
	}
}

func TestApplyForceReinstallsSameVersion(t *testing.T) {
	preserveTestGlobals(t)
	guestasset.Version = "v1.0.0"
	cacheFile = func() string { return filepath.Join(t.TempDir(), "update.json") }
	target := filepath.Join(t.TempDir(), "gantry")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return target, nil }
	payload := minimalNativeBinary(t)
	sum := sha256.Sum256(payload)
	asset, _ := platformAsset(runtime.GOOS, runtime.GOARCH)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/latest":
			_, _ = writer.Write([]byte(`{"tag_name":"v1.0.0"}`))
		case "/download/v1.0.0/" + asset + ".sha256":
			_, _ = fmt.Fprintf(writer, "%s  %s\n", hex.EncodeToString(sum[:]), asset)
		case "/download/v1.0.0/" + asset:
			_, _ = writer.Write(payload)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	latestReleaseEndpoint = server.URL + "/latest"
	releaseDownloadBase = server.URL + "/download"
	httpClient = server.Client()

	result, err := ApplyForce(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Previous != "v1.0.0" || result.Installed != "v1.0.0" || result.Executable != target {
		t.Fatalf("result = %+v", result)
	}
	if got, _ := os.ReadFile(target); string(got) != string(payload) {
		t.Fatal("forced update did not replace the executable")
	}
}

func TestApplyRejectsChecksumMismatch(t *testing.T) {
	preserveTestGlobals(t)
	guestasset.Version = "v1.0.0"
	cacheFile = func() string { return filepath.Join(t.TempDir(), "update.json") }
	target := filepath.Join(t.TempDir(), "gantry")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return target, nil }
	payload := minimalNativeBinary(t)
	asset, _ := platformAsset(runtime.GOOS, runtime.GOARCH)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/latest":
			_, _ = writer.Write([]byte(`{"tag_name":"v1.1.0"}`))
		case "/download/v1.1.0/" + asset + ".sha256":
			_, _ = writer.Write([]byte(strings.Repeat("0", 64)))
		case "/download/v1.1.0/" + asset:
			_, _ = writer.Write(payload)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	latestReleaseEndpoint = server.URL + "/latest"
	releaseDownloadBase = server.URL + "/download"
	httpClient = server.Client()

	if _, err := Apply(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("Apply mismatch error = %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "old" {
		t.Fatalf("target changed after mismatch: %q", got)
	}
}

func minimalNativeBinary(t *testing.T) []byte {
	t.Helper()
	header := make([]byte, 64)
	switch runtime.GOOS {
	case "linux":
		copy(header, "\x7fELF")
		header[5] = 1
		machine := uint16(62)
		if runtime.GOARCH == "arm64" {
			machine = 183
		}
		binary.LittleEndian.PutUint16(header[18:20], machine)
	case "darwin":
		binary.LittleEndian.PutUint32(header[:4], 0xfeedfacf)
		binary.LittleEndian.PutUint32(header[4:8], 0x0100000c)
	default:
		t.Fatalf("native test binary unsupported on %s", runtime.GOOS)
	}
	return header
}
