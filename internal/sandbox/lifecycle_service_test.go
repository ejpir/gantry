package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"
)

func TestLifecycleCreateRejectsExistingBeforeResolvingAssets(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	dir := layout.Dir("saved")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	before := []byte("saved configuration must not be replaced")
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), before, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewLifecycleService().Start(context.Background(), lifecycle.StartRequest{Name: "saved", Mode: lifecycle.Create}, nil)
	if !errors.Is(err, lifecycle.ErrAlreadyExists) {
		t.Fatalf("create error=%v", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("create changed existing configuration")
	}
}

func TestLaunchCancellationReapsUncommittedDaemon(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	process := &fakeSandboxDaemon{pid: os.Getpid(), wait: make(chan error, 1)}
	spawned := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := launchSandboxLockedCore(ctx, "cancelled", config.RunConfig{}, nil, true, true,
			func(*exec.Cmd) (sandboxDaemonProcess, error) { close(spawned); return process, nil }, nil, nil)
		result <- err
	}()
	select {
	case <-spawned:
	case <-time.After(5 * time.Second):
		t.Fatal("launch did not spawn")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || !process.killed.Load() {
			t.Fatalf("cancel error=%v killed=%v", err, process.killed.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled launch did not reap")
	}
}

func TestLifecycleCancellationBeforeStartDoesNoIO(t *testing.T) {
	root := filepath.Join(t.TempDir(), "unused")
	t.Setenv("GANTRY_HOME", root)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewLifecycleService().Start(ctx, lifecycle.StartRequest{Name: "cancelled", Mode: lifecycle.Create}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled request touched storage: %v", err)
	}
}

func TestDaemonHandshakeCancellationClosesBlockedPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	process := &execSandboxDaemon{handshake: writer}
	done := make(chan error, 1)
	go func() { done <- process.SendHandshake(ctx, strings.Repeat("x", 1<<20)) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("handshake error = %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = writer.Close()
		t.Fatal("cancelled handshake stayed blocked")
	}
}
