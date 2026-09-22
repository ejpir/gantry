package gutil

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestFileSizeReportsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset")
	payload := []byte("gantry-file-size-probe")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(7, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	size, err := FileSize(f)
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(payload)) {
		t.Fatalf("size = %d, want %d", size, len(payload))
	}
	offset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if offset != 7 {
		t.Fatalf("descriptor offset = %d, want the 7 the caller left behind", offset)
	}
}

func TestFileSizeSurfacesStructuralErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := FileSize(f); err == nil || errors.Is(err, os.ErrPermission) {
		t.Fatalf("closed descriptor must surface its original error, got %v", err)
	}
}
