package sandbox

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type fakeSandboxDaemon struct {
	pid    int
	wait   chan error
	killed atomic.Bool
}

func (p *fakeSandboxDaemon) PID() int { return p.pid }
func (p *fakeSandboxDaemon) SendHandshake(string) error {
	return nil
}
func (p *fakeSandboxDaemon) Wait() error {
	return <-p.wait
}
func (p *fakeSandboxDaemon) Kill() error {
	p.killed.Store(true)
	select {
	case p.wait <- errors.New("fake daemon killed"):
	default:
	}
	return nil
}

func TestConcurrentLaunchesCannotClobberOrDoubleSpawn(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	name := "same-name"
	firstConfig := RunConfig{MemMB: 111, VCPUs: 1}
	secondConfig := RunConfig{MemMB: 222, VCPUs: 1}
	process := &fakeSandboxDaemon{pid: os.Getpid(), wait: make(chan error, 1)}
	spawned := make(chan struct{}, 1)
	var spawnCount atomic.Int32
	spawn := func(*exec.Cmd) (sandboxDaemonProcess, error) {
		spawnCount.Add(1)
		spawned <- struct{}{}
		return process, nil
	}

	firstResult := make(chan int, 1)
	go func() {
		firstResult <- launchSandboxModeWithSpawner(name, firstConfig, nil, true, false, spawn)
	}()
	select {
	case <-spawned:
	case <-time.After(5 * time.Second):
		t.Fatal("first launch did not reach the spawn boundary")
	}

	if status := launchSandboxModeWithSpawner(name, secondConfig, nil, true, false, spawn); status == 0 {
		t.Fatal("concurrent launch unexpectedly succeeded")
	}
	if got := spawnCount.Load(); got != 1 {
		t.Fatalf("daemon spawn count = %d, want 1", got)
	}
	var persisted RunConfig
	configData, err := os.ReadFile(filepath.Join(sandboxDir(name), "sandbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(configData, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.MemMB != firstConfig.MemMB {
		t.Fatalf("concurrent launch clobbered configuration: MemMB = %d, want %d", persisted.MemMB, firstConfig.MemMB)
	}

	lifetime, err := holdSandboxLock(sandboxDir(name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandboxDir(name), "ready"), []byte("1\n"), 0o600); err != nil {
		_ = lifetime.Close()
		t.Fatal(err)
	}
	select {
	case status := <-firstResult:
		_ = lifetime.Close()
		if status != 0 {
			t.Fatalf("first launch status = %d, want 0", status)
		}
	case <-time.After(5 * time.Second):
		_ = lifetime.Close()
		t.Fatal("first launch did not observe readiness")
	}
	process.wait <- nil
}

func TestReadinessWithoutLifetimeLockAbortsLaunch(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	name := "no-handoff"
	process := &fakeSandboxDaemon{pid: os.Getpid(), wait: make(chan error, 1)}
	spawned := make(chan struct{}, 1)
	spawn := func(*exec.Cmd) (sandboxDaemonProcess, error) {
		spawned <- struct{}{}
		return process, nil
	}

	result := make(chan int, 1)
	go func() {
		result <- launchSandboxModeWithSpawner(name, RunConfig{}, nil, true, false, spawn)
	}()
	select {
	case <-spawned:
	case <-time.After(5 * time.Second):
		t.Fatal("launch did not reach the spawn boundary")
	}
	if err := os.WriteFile(filepath.Join(sandboxDir(name), "ready"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case status := <-result:
		if status == 0 {
			t.Fatal("readiness committed without the daemon lifetime lock")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("launch did not reject an uncommitted readiness marker")
	}
	if !process.killed.Load() {
		t.Fatal("uncommitted daemon was not killed")
	}
}

func TestLaunchHonorsDaemonLifetimeLockWithoutPID(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	name := "locked"
	dir := sandboxDir(name)
	if err := createSandboxDirectory(dir); err != nil {
		t.Fatal(err)
	}
	lifetime, err := holdSandboxLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lifetime.Close() }()

	var spawnCount atomic.Int32
	spawn := func(*exec.Cmd) (sandboxDaemonProcess, error) {
		spawnCount.Add(1)
		return nil, nil
	}
	if status := launchSandboxModeWithSpawner(name, RunConfig{}, nil, false, false, spawn); status == 0 {
		t.Fatal("launch ignored daemon lifetime lock")
	}
	if got := spawnCount.Load(); got != 0 {
		t.Fatalf("daemon spawned %d times while lifetime lock was held", got)
	}
}
