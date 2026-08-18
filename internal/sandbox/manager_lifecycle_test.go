package sandbox

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/manager"
)

func TestManagerCreateRejectsUncachedImageWithoutNetwork(t *testing.T) {
	t.Setenv("GANTRY_HOME", filepath.Join(t.TempDir(), "sandboxes"))
	t.Setenv("GANTRY_IMAGES", t.TempDir())
	dir := t.TempDir()
	rootfs := filepath.Join(dir, "rootfs.erofs")
	// Resolution reaches the cache-only miss only after kernel architecture
	// detection. Use a minimal x86-64 ELF header so the test is independent of
	// the host executable format (PE on Windows, Mach-O on macOS).
	kernel := filepath.Join(dir, "kernel")
	kernelHeader := make([]byte, 0x40)
	copy(kernelHeader, "\x7fELF")
	kernelHeader[18] = 62 // EM_X86_64, little endian.
	if err := os.WriteFile(kernel, kernelHeader, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootfs, []byte("rootfs"), 0o600); err != nil {
		t.Fatal(err)
	}
	no := false
	encoded, _ := json.Marshal(map[string]any{
		"name": "offline", "image": "example.invalid/app:latest",
		"kernel": kernel, "rootfs": rootfs, "rw": &no, "net": &no,
	})
	response := httptest.NewRecorder()
	httpRequest := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", bytes.NewReader(encoded))
	manager.NewHandler(managerLifecycle{}).ServeHTTP(response, httpRequest)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "gantry image pull") {
		t.Fatalf("create = %d %s", response.Code, response.Body.String())
	}
}
