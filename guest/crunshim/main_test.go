//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	rc := supervise([]string{"crun"}, false)
	elapsed := time.Since(start)

	os.Stderr = oldErr
	w.Close()
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
	stubRuntime := func(t *testing.T, stateRC int) {
		stub := filepath.Join(t.TempDir(), "runsc")
		script := fmt.Sprintf("#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = state ] && exit %d; done\nexit 1\n", stateRC)
		if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		realRuntime = stub
	}

	t.Run("live state keeps filestore", func(t *testing.T) {
		_, args, filestore := setup(t)
		stubRuntime(t, 0)
		sweepFilestores(args)
		if _, err := os.Stat(filestore); err != nil {
			t.Error("duplicate create against a live container must not delete its filestore")
		}
	})

	t.Run("no state sweeps stale filestore", func(t *testing.T) {
		_, args, filestore := setup(t)
		stubRuntime(t, 1)
		sweepFilestores(args)
		if _, err := os.Stat(filestore); !os.IsNotExist(err) {
			t.Errorf("stale filestore not swept: %v", err)
		}
	})

	t.Run("undetermined id skips sweep", func(t *testing.T) {
		_, args, filestore := setup(t)
		stubRuntime(t, 1)
		args[len(args)-1] = "--no-pivot" // no container id to probe
		sweepFilestores(args)
		if _, err := os.Stat(filestore); err != nil {
			t.Error("sweep without a container id must not touch filestores")
		}
	})
}
