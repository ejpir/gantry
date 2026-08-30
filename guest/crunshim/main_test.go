//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestSuperviseReturnsWithParkedGrandchild reproduces the 2026-07 runsc
// hang: the child exits 0 immediately but a grandchild keeps the
// inherited stdout/stderr pipe open (runsc create's parked gofer/sandbox
// do exactly this). supervise must return on the child's exit status
// (via WaitDelay), not block on pipe EOF.
func TestSuperviseReturnsWithParkedGrandchild(t *testing.T) {
	switch os.Getenv("CRUNSHIM_TEST_HELPER") {
	case "child":
		self, err := os.Executable() // supervise rewrites argv[0] to "crun"
		if err != nil {
			os.Exit(2)
		}
		gc := exec.Command(self)
		gc.Env = append(os.Environ(), "CRUNSHIM_TEST_HELPER=grandchild")
		gc.Stdout, gc.Stderr = os.Stdout, os.Stderr
		if err := gc.Start(); err != nil {
			os.Exit(2)
		}
		fmt.Println("crunshim-test-marker") // supervise must replay this
		os.Exit(0)                          // exit immediately; grandchild holds the pipes
	case "grandchild":
		time.Sleep(60 * time.Second) // parked for the "container lifetime"
		os.Exit(0)
	}

	old := realRuntime
	realRuntime = os.Args[0]
	defer func() { realRuntime = old }()
	t.Setenv("CRUNSHIM_TEST_HELPER", "child")

	// capture the replay on our stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outc := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(r); outc <- b }()
	oldErr := os.Stderr
	os.Stderr = w

	start := time.Now()
	rc := supervise([]string{"crun"}, false, false)
	elapsed := time.Since(start)

	os.Stderr = oldErr
	_ = w.Close()
	replayed := string(<-outc)

	if rc != 0 {
		t.Fatalf("supervise rc = %d, want 0", rc)
	}
	if elapsed > 15*time.Second {
		t.Fatalf("supervise blocked on the inherited pipe for %v; temp-file stdio not effective", elapsed)
	}
	if !strings.Contains(replayed, "crunshim-test-marker") {
		t.Fatalf("child output was not replayed to stderr: %q", replayed)
	}
}

// TestSuperviseExecStdioPassthrough pins the 2026-08 session regression:
// in exec mode the child's stdio must reach OUR stdout/stderr live (the
// vminitd session pipes) — the temp-file capture used for create/start
// black-holed every interactive session. And supervise must still
// return at child exit despite the parked grandchild holding the same
// fds (inherited *os.File -> no copy goroutines -> Wait doesn't wait
// for pipe EOF).
func TestSuperviseExecStdioPassthrough(t *testing.T) {
	switch os.Getenv("CRUNSHIM_TEST_HELPER") {
	case "child":
		self, err := os.Executable()
		if err != nil {
			os.Exit(2)
		}
		gc := exec.Command(self)
		gc.Env = append(os.Environ(), "CRUNSHIM_TEST_HELPER=grandchild")
		gc.Stdout, gc.Stderr = os.Stdout, os.Stderr
		if err := gc.Start(); err != nil {
			os.Exit(2)
		}
		fmt.Println("crunshim-test-marker") // must reach the session live
		os.Exit(0)
	case "grandchild":
		time.Sleep(60 * time.Second)
		os.Exit(0)
	}

	old := realRuntime
	realRuntime = os.Args[0]
	defer func() { realRuntime = old }()
	t.Setenv("CRUNSHIM_TEST_HELPER", "child")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// Both ends: anything but a swapped fd here is inherited by the
	// child AND its parked grandchild — the grandchild would hold the
	// test binary's real stderr pipe open for its 60s lifetime and the
	// go-test driver then fails the package with "Test I/O incomplete".
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w

	start := time.Now()
	rc := supervise([]string{"crun", "exec", "sb"}, false, false)
	elapsed := time.Since(start)

	os.Stdout, os.Stderr = oldOut, oldErr
	// The parked grandchild holds the write end for a minute, so do NOT
	// wait for EOF: read what arrived, with a deadline.
	_ = r.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	live := string(buf[:n])
	_ = w.Close()
	_ = r.Close()

	if rc != 0 {
		t.Fatalf("supervise rc = %d, want 0", rc)
	}
	if elapsed > 15*time.Second {
		t.Fatalf("exec supervise blocked for %v on the parked grandchild", elapsed)
	}
	if !strings.Contains(live, "crunshim-test-marker") {
		t.Fatalf("exec stdio did not reach our stdout live: %q", live)
	}
}

func TestSuperviseMarkedCreateStdioPassthrough(t *testing.T) {
	if os.Getenv("CRUNSHIM_STDIO_CREATE_HELPER") == "1" {
		fmt.Println("marked-create-output")
		os.Exit(0)
	}
	old := realRuntime
	realRuntime = os.Args[0]
	defer func() { realRuntime = old }()
	t.Setenv("CRUNSHIM_STDIO_CREATE_HELPER", "1")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	rc := supervise([]string{"crun", "create", "sb-session-1"}, false, true)
	os.Stdout, os.Stderr = oldOut, oldErr
	_ = w.Close()
	output, _ := io.ReadAll(r)
	_ = r.Close()

	if rc != 0 {
		t.Fatalf("supervise rc = %d, want 0", rc)
	}
	if !strings.Contains(string(output), "marked-create-output") {
		t.Fatalf("marked create output did not reach runtime stdio: %q", output)
	}
}

func TestHangDumpHelperProcess(t *testing.T) {
	if os.Getenv("CRUNSHIM_HANG_DUMP_HELPER") == "" {
		return
	}
	time.Sleep(60 * time.Second)
}

func TestSuperviseHangDumpDoesNotSignalUnrelatedRunscProcess(t *testing.T) {
	helperArgs := []string{"-test.run=^TestHangDumpHelperProcess$"}
	victim := exec.Command(os.Args[0], helperArgs...)
	victim.Args[0] = "runsc-sandbox-unrelated"
	victim.Env = replaceTestEnvironment("CRUNSHIM_HANG_DUMP_HELPER", "victim")
	victim.Stdout, victim.Stderr = io.Discard, io.Discard
	if err := victim.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = victim.Process.Kill()
		_ = victim.Wait()
	}()
	if err := victim.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("unrelated runsc-like process did not start: %v", err)
	}

	oldRuntime, oldDelay := realRuntime, hangDumpDelay
	realRuntime, hangDumpDelay = os.Args[0], 100*time.Millisecond
	defer func() { realRuntime, hangDumpDelay = oldRuntime, oldDelay }()
	t.Setenv("CRUNSHIM_HANG_DUMP_HELPER", "runtime")

	if code := supervise(append([]string{"crun"}, helperArgs...), true, false); code == 0 {
		t.Fatal("hang dump did not terminate the supervised runtime child")
	}
	if err := victim.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("hang dump signaled unrelated runsc-like process: %v", err)
	}
}

func replaceTestEnvironment(name, value string) []string {
	prefix := name + "="
	environment := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, prefix) {
			environment = append(environment, entry)
		}
	}
	return append(environment, prefix+value)
}

func TestInsertFlags(t *testing.T) {
	in := []string{"/sbin/crun", "--root", "/run/runc", "--debug", "--log", "/run/bundles/sb/log.json", "--log-format", "json", "create", "--bundle", "/run/bundles/sb", "--pid-file", "/run/bundles/sb/init.pid", "--console-socket", "/tmp/pty/pty.sock", "sb"}
	out := insertFlags(append([]string(nil), in...), true)
	t.Logf("debug=true : %v", out)
	out2 := insertFlags(append([]string(nil), in...), false)
	t.Logf("debug=false: %v", out2)
	if !strings.Contains(strings.Join(out, " "), "--log /dev/console") {
		t.Errorf("debug=true: --log not rewritten: %v", out)
	}
	if !strings.Contains(strings.Join(out2, " "), "--log /run/bundles/sb/log.json") {
		t.Errorf("debug=false: --log must stay: %v", out2)
	}
	// The per-arch default platform is injected (amd64 pins ptrace — the
	// slim guest kernel hangs systrap's newSubprocess) unless the caller
	// already chose one. /proc/cmdline on the test host has no
	// crunshim.platform= knob, so platformChoice() == defaultPlatform.
	joined := strings.Join(out2, " ")
	if defaultPlatform != "" && !strings.Contains(joined, "--platform="+defaultPlatform) {
		t.Errorf("default platform not injected: %v", out2)
	}
	withPlatform := insertFlags(append(append([]string(nil), in...), "--platform=systrap"), false)
	if n := strings.Count(strings.Join(withPlatform, " "), "--platform="); n != 1 {
		t.Errorf("caller platform must win, got %d --platform flags: %v", n, withPlatform)
	}
	// Presence is by flag NAME: a caller --directfs=true must not be
	// second-guessed by our --directfs=false.
	withDirectfs := insertFlags(append(append([]string(nil), in...), "--directfs=true"), false)
	if strings.Contains(strings.Join(withDirectfs, " "), "--directfs=false") {
		t.Errorf("caller --directfs=true overridden: %v", withDirectfs)
	}
	if !strings.Contains(joined, "--overlay2=none") {
		t.Errorf("Gantry rootfs must bypass runsc's redundant overlay: %v", out2)
	}
	withOverlay := insertFlags(append(append([]string(nil), in...), "--overlay2=all:memory"), false)
	if n := strings.Count(strings.Join(withOverlay, " "), "--overlay2="); n != 1 {
		t.Errorf("caller overlay mode must win, got %d --overlay2 flags: %v", n, withOverlay)
	}
}

func TestRuntimeStdioPassthroughMarker(t *testing.T) {
	bundle := t.TempDir()
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), []byte(`{
		"annotations":{"io.gantry.runtime-stdio-passthrough":"true"}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"crun", "create", "--bundle", bundle, "sb-session-1"}
	if !runtimeStdioPassthrough(args) {
		t.Fatal("marked workload create did not request runtime stdio passthrough")
	}
	if runtimeStdioPassthrough([]string{"crun", "start", "sb-session-1"}) {
		t.Fatal("non-create command requested runtime stdio passthrough")
	}
}

// TestSweepFilestores guards the stale-filestore sweep: a duplicate create
// against a live container must leave its in-use filestore alone (runsc
// create then fails with AlreadyExists), while a post-reboot bundle with
// no runtime state gets swept.
func TestSweepFilestores(t *testing.T) {
	old := realRuntime
	defer func() { realRuntime = old }()

	setup := func(t *testing.T) (bundle string, args []string, filestore string) {
		dir := t.TempDir()
		bundle = filepath.Join(dir, "bundle")
		if err := os.MkdirAll(filepath.Join(bundle, "rootfs"), 0o755); err != nil {
			t.Fatal(err)
		}
		filestore = filepath.Join(bundle, "rootfs", ".gvisor.filestore.sb")
		if err := os.WriteFile(filestore, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		args = []string{"crun", "--root", filepath.Join(dir, "runroot"), "create", "--bundle", bundle, "sb"}
		return bundle, args, filestore
	}
	// stubRuntime fakes runsc's `list --quiet`: "present" prints the
	// container id, "absent" prints nothing successfully, "error" fails.
	stubRuntime := func(t *testing.T, mode string) {
		stub := filepath.Join(t.TempDir(), "runsc")
		behavior := map[string]string{
			"present": "echo sb; exit 0",
			"absent":  "exit 0",
			"error":   "exit 1",
		}[mode]
		script := fmt.Sprintf("#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = list ] && { %s; }; done\nexit 1\n", behavior)
		if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		realRuntime = stub
	}

	t.Run("live state keeps filestore", func(t *testing.T) {
		_, args, filestore := setup(t)
		stubRuntime(t, "present")
		sweepFilestores(args)
		if _, err := os.Stat(filestore); err != nil {
			t.Error("duplicate create against a live container must not delete its filestore")
		}
	})

	t.Run("no state sweeps only matching stale filestore", func(t *testing.T) {
		bundle, args, filestore := setup(t)
		sibling := filepath.Join(bundle, "rootfs", ".gvisor.filestore.other-live-task")
		if err := os.WriteFile(sibling, []byte("live"), 0o644); err != nil {
			t.Fatal(err)
		}
		stubRuntime(t, "absent")
		sweepFilestores(args)
		if _, err := os.Stat(filestore); !os.IsNotExist(err) {
			t.Errorf("stale filestore not swept: %v", err)
		}
		if _, err := os.Stat(sibling); err != nil {
			t.Errorf("another container's filestore was removed: %v", err)
		}
	})

	t.Run("probe error keeps filestore", func(t *testing.T) {
		_, args, filestore := setup(t)
		stubRuntime(t, "error")
		sweepFilestores(args)
		if _, err := os.Stat(filestore); err != nil {
			t.Error("a failed state probe must fail closed, not delete a potentially live filestore")
		}
	})

	t.Run("undetermined id skips sweep", func(t *testing.T) {
		_, args, filestore := setup(t)
		stubRuntime(t, "absent")
		args[len(args)-1] = "--no-pivot" // no container id to probe
		sweepFilestores(args)
		if _, err := os.Stat(filestore); err != nil {
			t.Error("sweep without a container id must not touch filestores")
		}
	})
}
