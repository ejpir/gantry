package sandbox

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a bytes.Buffer safe for concurrent writer/reader — the
// interactive-echo test polls output while the copy goroutine is still
// writing (a plain bytes.Buffer trips the race detector there).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

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
	var out syncBuffer
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
	_ = pw.Close()
	if status := <-statusCh; status != 7 {
		t.Fatalf("status = %d, want 7", status)
	}
	if got := out.String(); got != "ls -la\r\n" {
		t.Fatalf("output = %q, trailer leaked", got)
	}
}

// A guest streaming "\x00GANTRY-EXIT " + digits while withholding the
// terminating NUL must not make the attach client retain unbounded memory:
// more digits than an int can hold provably never parse as a status.
func TestExitTrailerRejectsOverlongStatus(t *testing.T) {
	pr, pw := io.Pipe()
	var out syncBuffer
	statusCh := make(chan int, 1)
	go func() { statusCh <- copyStrippingExitTrailer(&out, pr) }()

	flood := "99999999999999999999" // 20 digits > int64 max
	in := exitTrailerPrefix + flood
	if _, err := pw.Write([]byte(in + flood)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for out.Len() < len(in)+len(flood) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := out.String(); got != in+flood {
		t.Fatalf("overlong possible trailer remained held: out = %q", got)
	}
	_ = pw.Close()
	if status := <-statusCh; status != 0 {
		t.Fatalf("status = %d, want 0", status)
	}
}

// The same flood drip-fed in chunks while the stream stays open: retained
// bytes must stay bounded (everything flushes through as data), and a later
// LEGITIMATE trailer still parses after the false alarm.
func TestExitTrailerDigitFloodStaysBounded(t *testing.T) {
	pr, pw := io.Pipe()
	var out syncBuffer
	statusCh := make(chan int, 1)
	go func() { statusCh <- copyStrippingExitTrailer(&out, pr) }()

	if _, err := pw.Write([]byte(exitTrailerPrefix)); err != nil {
		t.Fatal(err)
	}
	chunk := []byte("99999999999999999999999999999999")
	for i := 0; i < 64; i++ { // ~2 KiB of digits, stream stays open
		if _, err := pw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	// a real trailer for the actual exit status
	if _, err := pw.Write([]byte(exitTrailerPrefix + "3\x00")); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	if status := <-statusCh; status != 3 {
		t.Fatalf("status = %d, want 3", status)
	}
	wantLen := len(exitTrailerPrefix) + 64*len(chunk)
	if got := out.String(); len(got) != wantLen {
		t.Fatalf("output length = %d, trailer bytes leaked", len(got))
	}
}

// parseExitTrailer unit boundaries: max int64 digits parse, one more rejects.
func TestParseExitTrailerDigitBound(t *testing.T) {
	max := "9223372036854775807" // int64 max, 19 digits
	if st, ok, undecided := parseExitTrailer([]byte(exitTrailerPrefix + max + "\x00")); !ok || undecided || st != 1<<63-1 {
		t.Fatalf("int64 max trailer: st=%d ok=%v undecided=%v", st, ok, undecided)
	}
	if _, _, undecided := parseExitTrailer([]byte(exitTrailerPrefix + max)); !undecided {
		t.Fatal("19 unterminated digits should still be undecided")
	}
	if _, _, undecided := parseExitTrailer([]byte(exitTrailerPrefix + max + "0")); undecided {
		t.Fatal("20 digits must be rejected outright")
	}
	if _, ok, _ := parseExitTrailer([]byte(exitTrailerPrefix + max + "0\x00")); ok {
		t.Fatal("20-digit terminated value must not parse as a status")
	}
}
