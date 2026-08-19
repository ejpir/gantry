//go:build linux || darwin

package workertest

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestAssertStdinUnreadableReportsOpenPipeWithoutBlocking drives the probe
// with stdin as an open but empty pipe: the violation must be reported with
// exit status 97, not hang the helper (and the worker it confines) forever.
func TestAssertStdinUnreadableReportsOpenPipeWithoutBlocking(t *testing.T) {
	if os.Getenv("GANTRY_TEST_WORKER_STDIN_UNREADABLE") == "1" {
		AssertStdinUnreadable()
		return
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }() // held open: no data, no EOF

	cmd := exec.Command(os.Args[0], "-test.run", "^TestAssertStdinUnreadableReportsOpenPipeWithoutBlocking$")
	cmd.Env = append(os.Environ(), "GANTRY_TEST_WORKER_STDIN_UNREADABLE=1")
	cmd.Stdin = reader
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 97 {
			t.Fatalf("exit = %v, want status 97 (stdin readable violation)", err)
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("stdin probe blocked on an open pipe instead of reporting the violation")
	}
}
