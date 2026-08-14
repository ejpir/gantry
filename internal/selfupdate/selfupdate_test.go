package selfupdate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/guestasset"
)

func preserveTestGlobals(t *testing.T) {
	t.Helper()
	oldVersion := guestasset.Version
	oldEndpoint, oldBase := latestReleaseEndpoint, releaseDownloadBase
	oldClient, oldNow := httpClient, now
	oldCache, oldExecutable := cacheFile, executablePath
	t.Cleanup(func() {
		guestasset.Version = oldVersion
		latestReleaseEndpoint, releaseDownloadBase = oldEndpoint, oldBase
		httpClient, now = oldClient, oldNow
		cacheFile, executablePath = oldCache, oldExecutable
	})
}

func TestCheckFindsNewerStableRelease(t *testing.T) {
	preserveTestGlobals(t)
	guestasset.Version = "v1.2.3"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("User-Agent"); got != "gantry/v1.2.3" {
			t.Errorf("User-Agent = %q", got)
		}
		_ = json.NewEncoder(writer).Encode(releaseResponse{TagName: "v1.4.0"})
	}))
	defer server.Close()
	latestReleaseEndpoint = server.URL
	httpClient = server.Client()

	status, err := Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v1.2.3" || status.Latest != "v1.4.0" || !status.Available {
		t.Fatalf("status = %+v", status)
	}
}

func TestCheckSkipsDevelopmentBuild(t *testing.T) {
	preserveTestGlobals(t)
	guestasset.Version = "dev"
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer server.Close()
	latestReleaseEndpoint = server.URL
	httpClient = server.Client()

	status, err := Check(context.Background())
	if err != nil || status.Current != "dev" || status.Available || called {
		t.Fatalf("Check(dev) = (%+v, %v), request=%v", status, err, called)
	}
}

func TestCheckRejectsInvalidReleaseTag(t *testing.T) {
	preserveTestGlobals(t)
	guestasset.Version = "v1.2.3"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(releaseResponse{TagName: "latest"})
	}))
	defer server.Close()
	latestReleaseEndpoint = server.URL
	httpClient = server.Client()

	if _, err := Check(context.Background()); err == nil {
		t.Fatal("Check accepted a non-semver release tag")
	}
}

func TestCachedStatusAndRefreshWindow(t *testing.T) {
	preserveTestGlobals(t)
	guestasset.Version = "v2.0.0"
	currentTime := time.Date(2026, 8, 15, 1, 2, 3, 0, time.UTC)
	now = func() time.Time { return currentTime }
	path := filepath.Join(t.TempDir(), "cache", "update.json")
	cacheFile = func() string { return path }

	if err := writeCache(cacheEntry{CheckedAt: currentTime.Add(-time.Hour), Latest: "v2.1.0"}); err != nil {
		t.Fatal(err)
	}
	status, found, fresh := Cached()
	if !found || !fresh || !status.Available || status.Latest != "v2.1.0" {
		t.Fatalf("Cached = (%+v, found=%v, fresh=%v)", status, found, fresh)
	}

	currentTime = currentTime.Add(checkInterval)
	status, found, fresh = Cached()
	if !found || fresh || !status.Available {
		t.Fatalf("stale Cached = (%+v, found=%v, fresh=%v)", status, found, fresh)
	}
}

func TestPlatformAssetsMatchReleaseWorkflow(t *testing.T) {
	tests := map[string]string{
		"linux/amd64":   "gantry-linux-amd64",
		"linux/arm64":   "gantry-linux-arm64",
		"darwin/arm64":  "gantry-darwin-arm64",
		"windows/amd64": "gantry-windows-amd64.exe",
	}
	for platform, want := range tests {
		parts := splitPlatform(platform)
		got, err := platformAsset(parts[0], parts[1])
		if err != nil || got != want {
			t.Errorf("platformAsset(%s) = (%q, %v), want %q", platform, got, err, want)
		}
	}
	if _, err := platformAsset("darwin", "amd64"); err == nil {
		t.Fatal("unsupported platform was accepted")
	}
}

func splitPlatform(value string) [2]string {
	for i := range value {
		if value[i] == '/' {
			return [2]string{value[:i], value[i+1:]}
		}
	}
	return [2]string{value}
}

func TestWriteCacheUsesPrivateFile(t *testing.T) {
	preserveTestGlobals(t)
	path := filepath.Join(t.TempDir(), "nested", "update.json")
	cacheFile = func() string { return path }
	if err := writeCache(cacheEntry{CheckedAt: time.Now(), Latest: "v1.0.0"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows does not expose POSIX permission bits through FileMode; Chmod
	// succeeds but Stat reports the regular-file default (0666). Cache
	// creation and contents remain covered above on every platform.
	if runtime.GOOS == "windows" {
		return
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("cache mode = %o, want 600", got)
	}
}
