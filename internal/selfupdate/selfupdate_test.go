package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/guestasset"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

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

func TestCheckAcceptsGitHubReleaseMetadataLargerThan64KiB(t *testing.T) {
	preserveTestGlobals(t)
	guestasset.Version = "v1.2.3"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]string{
			"tag_name": "v1.4.0",
			"assets":   strings.Repeat("x", 80<<10),
		})
	}))
	defer server.Close()
	latestReleaseEndpoint = server.URL
	httpClient = server.Client()

	status, err := Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Latest != "v1.4.0" {
		t.Fatalf("Check = %+v", status)
	}
}

func TestCheckRetriesTruncatedReleaseMetadata(t *testing.T) {
	preserveTestGlobals(t)
	guestasset.Version = "v1.2.3"
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(writer, `{"tag_name":`)
			return
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
	if status.Latest != "v1.4.0" || calls.Load() != 2 {
		t.Fatalf("Check = %+v after %d calls", status, calls.Load())
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

func TestCanceledRefreshPreservesPositiveCache(t *testing.T) {
	preserveTestGlobals(t)
	guestasset.Version = "v2.0.0"
	currentTime := time.Date(2026, 8, 15, 1, 2, 3, 0, time.UTC)
	now = func() time.Time { return currentTime }
	path := filepath.Join(t.TempDir(), "update.json")
	cacheFile = func() string { return path }
	if err := writeCache(cacheEntry{CheckedAt: currentTime.Add(-checkInterval), Latest: "v2.1.0"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	httpClient = &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		close(started)
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	latestReleaseEndpoint = "https://updates.invalid/latest"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Refresh(ctx)
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Refresh cancellation error = %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("canceled refresh changed cache:\nbefore: %s\nafter:  %s", before, after)
	}
	status, found, _ := Cached()
	if !found || !status.Available || status.Latest != "v2.1.0" {
		t.Fatalf("Cached after cancellation = (%+v, found=%v)", status, found)
	}
}

func TestFailedRefreshRetainsLastDiscoveredRelease(t *testing.T) {
	preserveTestGlobals(t)
	guestasset.Version = "v2.0.0"
	currentTime := time.Date(2026, 8, 15, 1, 2, 3, 0, time.UTC)
	now = func() time.Time { return currentTime }
	path := filepath.Join(t.TempDir(), "update.json")
	cacheFile = func() string { return path }
	if err := writeCache(cacheEntry{CheckedAt: currentTime.Add(-checkInterval), Latest: "v2.1.0"}); err != nil {
		t.Fatal(err)
	}
	httpClient = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Status:     "503 Service Unavailable",
			Body:       io.NopCloser(strings.NewReader("unavailable")),
		}, nil
	})}
	latestReleaseEndpoint = "https://updates.invalid/latest"

	if _, err := Refresh(context.Background()); err == nil {
		t.Fatal("Refresh succeeded through a server failure")
	}
	entry, err := readCache()
	if err != nil {
		t.Fatal(err)
	}
	if !entry.Failed || entry.Latest != "v2.1.0" {
		t.Fatalf("failed refresh cache = %+v", entry)
	}
}

func TestOlderFailedRefreshCannotOverwriteNewerSuccess(t *testing.T) {
	preserveTestGlobals(t)
	guestasset.Version = "v2.0.0"
	baseTime := time.Date(2026, 8, 15, 1, 2, 3, 0, time.UTC)
	var clockCalls atomic.Int32
	now = func() time.Time {
		return baseTime.Add(time.Duration(clockCalls.Add(1)-1) * time.Second)
	}
	path := filepath.Join(t.TempDir(), "update.json")
	cacheFile = func() string { return path }
	latestReleaseEndpoint = "https://updates.invalid/latest"
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var requests atomic.Int32
	httpClient = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		if requests.Add(1) == 1 {
			close(firstStarted)
			<-releaseFirst
			return nil, errors.New("older check failed")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader(`{"tag_name":"v2.2.0"}`)),
		}, nil
	})}

	olderDone := make(chan error, 1)
	go func() {
		_, err := Refresh(context.Background())
		olderDone <- err
	}()
	<-firstStarted
	if _, err := Refresh(context.Background()); err != nil {
		t.Fatalf("newer refresh: %v", err)
	}
	close(releaseFirst)
	if err := <-olderDone; err == nil {
		t.Fatal("older failing refresh unexpectedly succeeded")
	}
	entry, err := readCache()
	if err != nil {
		t.Fatal(err)
	}
	if entry.Failed || entry.Latest != "v2.2.0" {
		t.Fatalf("out-of-order refresh cache = %+v", entry)
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
