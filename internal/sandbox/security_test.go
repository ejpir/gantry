package sandbox

import (
	"bytes"
	"testing"
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
