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

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

type fakeSandboxDaemon struct {
	pid    int
	wait   chan error
	killed atomic.Bool
}

func installDurabilityGate(t *testing.T) (entered <-chan struct{}, release chan<- error) {
	t.Helper()
	old := makeConfigDurable
	started := make(chan struct{}, 1)
	result := make(chan error, 1)
	makeConfigDurable = func(string) error {
		started <- struct{}{}
		return <-result
	}
	t.Cleanup(func() { makeConfigDurable = old })
	return started, result
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
	firstConfig := config.RunConfig{MemMB: 111, VCPUs: 1}
	secondConfig := config.RunConfig{MemMB: 222, VCPUs: 1}
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
	var persisted config.RunConfig
	configData, err := os.ReadFile(filepath.Join(layout.Dir(name), "sandbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(configData, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.MemMB != firstConfig.MemMB {
		t.Fatalf("concurrent launch clobbered configuration: MemMB = %d, want %d", persisted.MemMB, firstConfig.MemMB)
	}

	lifetime, err := layout.HoldLock(layout.Dir(name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout.Dir(name), "ready"), []byte("1\n"), 0o600); err != nil {
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

func TestLaunchOverlapsConfigDurabilityWithDaemonStartup(t *testing.T) {
	if !atomicfile.CanMakeDurableAfterCommit() {
		t.Skip("platform requires write-through replacement")
	}
	t.Setenv("GANTRY_HOME", t.TempDir())
	entered, release := installDurabilityGate(t)
	name := "durability-overlap"
	process := &fakeSandboxDaemon{pid: os.Getpid(), wait: make(chan error, 1)}
	spawned := make(chan struct{}, 1)
	spawn := func(*exec.Cmd) (sandboxDaemonProcess, error) {
		spawned <- struct{}{}
		return process, nil
	}
	result := make(chan int, 1)
	go func() {
		result <- launchSandboxModeWithSpawner(name, config.RunConfig{}, nil, true, false, spawn)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("durability barrier did not start")
	}
	select {
	case <-spawned:
	case <-time.After(5 * time.Second):
		t.Fatal("daemon startup waited for durability")
	}
	lifetime, err := layout.HoldLock(layout.Dir(name))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lifetime.Close() }()
	if err := os.WriteFile(filepath.Join(layout.Dir(name), "ready"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case status := <-result:
		t.Fatalf("launch completed before durability release with status %d", status)
	case <-time.After(150 * time.Millisecond):
	}
	release <- nil
	select {
	case status := <-result:
		if status != 0 {
			t.Fatalf("launch status = %d, want 0", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("launch did not complete after durability succeeded")
	}
	process.wait <- nil
}

func TestLaunchDurabilityFailureKillsUncommittedDaemon(t *testing.T) {
	if !atomicfile.CanMakeDurableAfterCommit() {
		t.Skip("platform requires write-through replacement")
	}
	t.Setenv("GANTRY_HOME", t.TempDir())
	entered, release := installDurabilityGate(t)
	name := "durability-failure"
	process := &fakeSandboxDaemon{pid: os.Getpid(), wait: make(chan error, 1)}
	spawned := make(chan struct{}, 1)
	spawn := func(*exec.Cmd) (sandboxDaemonProcess, error) {
		spawned <- struct{}{}
		return process, nil
	}
	result := make(chan int, 1)
	go func() {
		result <- launchSandboxModeWithSpawner(name, config.RunConfig{}, nil, true, false, spawn)
	}()
	<-entered
	<-spawned
	lifetime, err := layout.HoldLock(layout.Dir(name))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lifetime.Close() }()
	if err := os.WriteFile(filepath.Join(layout.Dir(name), "ready"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	release <- errors.New("sync failed")
	select {
	case status := <-result:
		if status == 0 {
			t.Fatal("launch succeeded despite durability failure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("launch did not fail after durability failure")
	}
	if !process.killed.Load() {
		t.Fatal("daemon was not killed after durability failure")
	}
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
		result <- launchSandboxModeWithSpawner(name, config.RunConfig{}, nil, true, false, spawn)
	}()
	select {
	case <-spawned:
	case <-time.After(5 * time.Second):
		t.Fatal("launch did not reach the spawn boundary")
	}
	if err := os.WriteFile(filepath.Join(layout.Dir(name), "ready"), []byte("1\n"), 0o600); err != nil {
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
	dir := layout.Dir(name)
	if err := localsec.CreateDir(dir); err != nil {
		t.Fatal(err)
	}
	lifetime, err := layout.HoldLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lifetime.Close() }()

	var spawnCount atomic.Int32
	spawn := func(*exec.Cmd) (sandboxDaemonProcess, error) {
		spawnCount.Add(1)
		return nil, nil
	}
	if status := launchSandboxModeWithSpawner(name, config.RunConfig{}, nil, false, false, spawn); status == 0 {
		t.Fatal("launch ignored daemon lifetime lock")
	}
	if got := spawnCount.Load(); got != 0 {
		t.Fatalf("daemon spawned %d times while lifetime lock was held", got)
	}
}
