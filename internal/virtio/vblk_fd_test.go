//go:build linux || darwin

package virtio

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNewBlkFileLocksDescriptor pins the single-writer rule to the open
// file description: a second writable attach through ANOTHER open of the
// same path fails even though NewBlkFile never sees the path.
func TestNewBlkFileLocksDescriptor(t *testing.T) {
	img := filepath.Join(t.TempDir(), "rwlayer.img")
	if err := os.WriteFile(img, make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	f1, err := os.OpenFile(img, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := NewBlkFile(f1, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blk.Close() }()

	f2, err := os.OpenFile(img, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f2.Close() }()
	if _, err := NewBlkFile(f2, true); err == nil {
		t.Fatal("second writable attach through a different descriptor succeeded")
	}

	// Read-only attaches share freely (cached images are shared by design).
	f3, err := os.Open(img)
	if err != nil {
		t.Fatal(err)
	}
	ro, err := NewBlkFile(f3, false)
	if err != nil {
		t.Fatalf("read-only attach beside the writer: %v", err)
	}
	_ = ro.Close()
}

// TestNewBlkFileReadOnlyFeatures keeps the read-only feature bit tied to
// the caller's flag, not to how the descriptor was opened.
func TestNewBlkFileReadOnlyFeatures(t *testing.T) {
	img := filepath.Join(t.TempDir(), "layer.erofs")
	if err := os.WriteFile(img, make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(img)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := NewBlkFile(f, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blk.Close() }()
	if f := blk.features(); f&(1<<BlkFRO) == 0 {
		t.Fatalf("read-only features = %#x (want RO)", f)
	}
}
