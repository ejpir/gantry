package sandbox

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// Sandbox names feed filepath.Join + os.RemoveAll: path traversal out of the
// sandbox root must be rejected before any subcommand sees the name.
func TestSandboxNameTraversal(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "../victim", "a/b", `a\b`, "a b", "a\u0000b"} {
		if validSandboxName(bad) {
			t.Fatalf("validSandboxName(%q) = true", bad)
		}
	}
	for _, good := range []string{"dev", "my-vm.2_test", "..ok"} {
		if !validSandboxName(good) {
			t.Fatalf("validSandboxName(%q) = false", good)
		}
	}
}

// The broker frames the task exit status as a NUL-delimited trailer; the
// attach client must strip it from the terminal stream and surface it.
func TestExitTrailer(t *testing.T) {
	in := "shell output\r\n" + exitTrailerPrefix + "42\x00"
	var out bytes.Buffer
	status := copyStrippingExitTrailer(&out, bytes.NewReader([]byte(in)))
	if status != 42 {
		t.Fatalf("status = %d, want 42", status)
	}
	if out.String() != "shell output\r\n" {
		t.Fatalf("output = %q, trailer not stripped", out.String())
	}

	// no trailer: plain pass-through, status 0
	out.Reset()
	status = copyStrippingExitTrailer(&out, bytes.NewReader([]byte("plain")))
	if status != 0 || out.String() != "plain" {
		t.Fatalf("plain stream: status=%d out=%q", status, out.String())
	}
}

// Interactive pty echo dribbles in byte-at-a-time: it must reach the
// terminal IMMEDIATELY (the fixed-size holdback this replaces showed
// nothing until 32 bytes accumulated — i.e. until you hit Enter).
func TestExitTrailerInteractiveEcho(t *testing.T) {
	pr, pw := io.Pipe()
	var out bytes.Buffer
	statusCh := make(chan int, 1)
	go func() { statusCh <- copyStrippingExitTrailer(&out, pr) }()

	// per-character echo: visible before EOF, one byte at a time
	if _, err := pw.Write([]byte("l")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for out.Len() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if out.Len() != 1 {
		t.Fatal("echo byte held back instead of written through")
	}
	if _, err := pw.Write([]byte("s -la\r\n")); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for out.Len() < 7 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := out.String(); got != "ls -la\r\n" {
		t.Fatalf("echo = %q", got)
	}

	// then the trailer (possibly split) is stripped and yields the status
	if _, err := pw.Write([]byte(exitTrailerPrefix + "7")); err != nil {
		t.Fatal(err)
	}
	if _, err := pw.Write([]byte("\x00")); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	if status := <-statusCh; status != 7 {
		t.Fatalf("status = %d, want 7", status)
	}
	if got := out.String(); got != "ls -la\r\n" {
		t.Fatalf("output = %q, trailer leaked", got)
	}
}
