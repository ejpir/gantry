package boundedlog

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadTailTruncationFlag(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small.log")
	if err := os.WriteFile(small, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tail, truncated, err := ReadTail(small, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if truncated || string(tail) != "hello\n" {
		t.Fatalf("small log tail = %q truncated=%v, want whole file untruncated", tail, truncated)
	}

	large := filepath.Join(dir, "large.log")
	content := bytes.Repeat([]byte("0123456789\n"), 1024)
	if err := os.WriteFile(large, content, 0o600); err != nil {
		t.Fatal(err)
	}
	tail, truncated, err = ReadTail(large, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Fatal("oversized log not marked truncated")
	}
	if len(tail) != 4096 || !bytes.HasSuffix(tail, []byte("0123456789\n")) {
		t.Fatalf("truncated tail length/suffix wrong: %d %q", len(tail), tail[len(tail)-16:])
	}

	if tail, truncated, err := ReadTail(small, 0); err != nil || truncated || tail != nil {
		t.Fatalf("zero limit = %q, %v, %v", tail, truncated, err)
	}
}

// TestDiagnosticTailMarksOnlyRealTruncation: a complete small log must not
// be mislabeled as a mid-line fragment just because it starts without '\n'.
func TestDiagnosticTailMarksOnlyRealTruncation(t *testing.T) {
	dir := t.TempDir()
	whole := filepath.Join(dir, "whole.log")
	if err := os.WriteFile(whole, []byte("complete first line\nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := DiagnosticTail("worker", whole)
	if err == nil || !strings.HasPrefix(err.Error(), "worker diagnostics:\ncomplete first line") {
		t.Fatalf("whole-log diagnostics = %v", err)
	}

	oversized := filepath.Join(dir, "oversized.log")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte("x"), diagnosticTailBytes+8), 0o600); err != nil {
		t.Fatal(err)
	}
	err = DiagnosticTail("worker", oversized)
	if err == nil || !strings.HasPrefix(err.Error(), "worker diagnostics:\n...") {
		t.Fatalf("truncated diagnostics lost the fragment marker: %.40q", err)
	}
}
