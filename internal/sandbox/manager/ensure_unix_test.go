//go:build linux || darwin

package manager

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func ensureTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GANTRY_HOME", filepath.Join(root, "sandboxes"))
	t.Setenv("GANTRY_MANAGER_SOCKET", "")
	return root
}

func TestEnsureHelperProcess(t *testing.T) {
	if os.Getenv("GANTRY_ENSURE_HELPER_TEST") != "1" {
		return
	}
	os.Exit(Cmd([]string{"--local-background"}, stubLifecycle{}))
}

func ensureTestLauncher(log *os.File) (*exec.Cmd, error) {
	command := exec.Command(os.Args[0], "-test.run=^TestEnsureHelperProcess$")
	command.Env = append(os.Environ(), "GANTRY_ENSURE_HELPER_TEST=1")
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	command.Stdout, command.Stderr = log, log
	return command, command.Start()
}

func stopEnsuredManager(t *testing.T, result ensureResult) {
	t.Helper()
	if result.PID == 0 {
		return
	}
	process, err := os.FindProcess(result.PID)
	if err == nil {
		_ = process.Signal(syscall.SIGTERM)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(result.Socket); errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = process.Kill()
	t.Error("ensured manager did not shut down cleanly")
}

func TestEnsureStartsOnceAndReusesManager(t *testing.T) {
	ensureTestRoot(t)
	path := SocketPath()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var starts atomic.Int32
	launch := func(log *os.File) (*exec.Cmd, error) {
		starts.Add(1)
		return ensureTestLauncher(log)
	}
	var wait sync.WaitGroup
	results := make(chan ensureResult, 6)
	for range 6 {
		wait.Go(func() {
			result, err := ensureLocalManager(ctx, path, launch)
			if err != nil {
				t.Errorf("ensure: %v", err)
				return
			}
			results <- result
		})
	}
	wait.Wait()
	close(results)
	for result := range results {
		if result.Started {
			t.Cleanup(func() { stopEnsuredManager(t, result) })
		}
		if result.Socket != path || result.Version != "v1" {
			t.Errorf("unexpected readiness: %+v", result)
		}
	}
	if starts.Load() != 1 {
		t.Fatalf("spawned %d managers, want 1", starts.Load())
	}
	if err := probeLocalManager(ctx, path); err != nil {
		t.Fatal(err)
	}
}

func serveProbeEndpoint(t *testing.T, path string, handler http.Handler) {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
}

func TestEnsureDoesNotLaunchForExistingOrIncompatibleEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		ok         bool
	}{
		{"healthy", `{"ok":true,"version":"v1"}`, 200, true},
		{"wrong-version", `{"ok":true,"version":"v2"}`, 200, false},
		{"not-ready", `{"ok":false,"version":"v1"}`, 200, false},
		{"bad-json", `not json`, 200, false},
		{"denied", `{"error":"denied"}`, 403, false},
		{"redirect", ``, 302, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ensureTestRoot(t)
			path := SocketPath()
			serveProbeEndpoint(t, path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/health" || r.Method != http.MethodGet {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Location", "http://127.0.0.1:9/")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			_, err := ensureLocalManager(context.Background(), path, func(*os.File) (*exec.Cmd, error) {
				t.Fatal("must not launch or replace this endpoint")
				return nil, nil
			})
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v, want success=%v", err, tc.ok)
			}
		})
	}
}

func TestEnsureRefusesUnsafeSocketAndLogPaths(t *testing.T) {
	for _, kind := range []string{"regular-endpoint", "symlink-endpoint", "public-parent", "symlink-log"} {
		t.Run(kind, func(t *testing.T) {
			root := ensureTestRoot(t)
			path := SocketPath()
			sentinel := filepath.Join(root, "sentinel")
			if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "regular-endpoint":
				if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink-endpoint":
				if err := os.Symlink(sentinel, path); err != nil {
					t.Fatal(err)
				}
			case "public-parent":
				if err := os.Chmod(root, 0o755); err != nil {
					t.Fatal(err)
				}
			case "symlink-log":
				if err := os.Symlink(sentinel, filepath.Join(root, "manager.log")); err != nil {
					t.Fatal(err)
				}
			}
			_, err := ensureLocalManager(context.Background(), path, func(*os.File) (*exec.Cmd, error) {
				t.Fatal("unsafe paths must not launch a manager")
				return nil, nil
			})
			if err == nil {
				t.Fatal("unsafe path accepted")
			}
			if data, _ := os.ReadFile(sentinel); string(data) != "unchanged" {
				t.Fatal("sentinel changed")
			}
		})
	}
}

func TestEnsureStaleSocketIsRecoveredByOrdinaryServerOwnership(t *testing.T) {
	ensureTestRoot(t)
	path := SocketPath()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	_ = listener.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := ensureLocalManager(ctx, path, ensureTestLauncher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopEnsuredManager(t, result) })
	if !result.Started {
		t.Fatal("stale endpoint was not recovered")
	}
}

func TestEnsureRefusesSavedFeed(t *testing.T) {
	root := ensureTestRoot(t)
	state := filepath.Join(root, "manager-state", "policy-feeds", "organization")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := ensureLocalManager(ctx, SocketPath(), ensureTestLauncher)
	if err == nil || !strings.Contains(err.Error(), "policy-feed") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(SocketPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("automatic manager published a socket: %v", err)
	}
}

func TestEnsureRejectsRetargetingAndRemoteOptions(t *testing.T) {
	ensureTestRoot(t)
	if _, err := ensureDefaultManager(context.Background(), "/other/manager.sock"); err == nil {
		t.Fatal("retargeted default startup")
	}
	for _, args := range [][]string{
		{"--ensure", "--listen", "unix:///other/socket"},
		{"--ensure", "--self-signed"},
		{"--ensure", "--mint-token"},
		{"--ensure", "--policy-feed", "feed.json"},
		{"--ensure", "--local-background"},
	} {
		if code := Cmd(args, stubLifecycle{}); code != 2 {
			t.Errorf("Cmd(%v)=%d, want usage error", args, code)
		}
	}
	t.Setenv("GANTRY_MANAGER_SOCKET", SocketPath())
	if _, err := ensureDefaultManager(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "connect-only") {
		t.Fatalf("got %v", err)
	}
}

func TestEnsureReadinessIsBounded(t *testing.T) {
	ensureTestRoot(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	var child *exec.Cmd
	_, err := ensureLocalManager(ctx, SocketPath(), func(log *os.File) (*exec.Cmd, error) {
		child = exec.Command("sleep", "30")
		child.Stdout, child.Stderr = log, log
		return child, child.Start()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestEnsurePreservesExistingStateOwner(t *testing.T) {
	root := ensureTestRoot(t)
	state := filepath.Join(root, "manager-state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := layout.HoldLock(state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := ensureLocalManager(ctx, SocketPath(), ensureTestLauncher); err == nil {
		t.Fatal("automatic start displaced an existing manager owner")
	}
	if second, err := layout.HoldLock(state); err == nil {
		_ = second.Close()
		t.Fatal("existing state lock was released")
	}
	if _, err := os.Lstat(SocketPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("published endpoint: %v", err)
	}
}

func TestEnsureCanceledBeforeStartupDoesNotLaunch(t *testing.T) {
	ensureTestRoot(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ensureLocalManager(ctx, SocketPath(), func(*os.File) (*exec.Cmd, error) {
		t.Fatal("canceled ensure launched a child")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestEnsureProbeBoundsResponse(t *testing.T) {
	ensureTestRoot(t)
	serveProbeEndpoint(t, SocketPath(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(managerapi.Health{OK: true, Version: strings.Repeat("x", 5000)})
	}))
	if err := probeLocalManager(context.Background(), SocketPath()); err == nil || errors.Is(err, errManagerAbsent) {
		t.Fatalf("got %v", err)
	}
}
