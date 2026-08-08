//go:build linux || darwin

package virtio

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestShareHubPinnedNeedsNoPathAccess(t *testing.T) {
	// Regression for the confined-worker hot-add failure (TUI:
	// "share.prepare: create loopback export: lstat /Users: operation
	// not permitted"): export creation and the special-file policy
	// must run without ANY host path access — a confined worker
	// denies every absolute-path syscall. A bogus path string with a
	// valid pinned root descriptor simulates that worker.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	hub, err := NewShareHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	fuseInitHub(t, hub)

	prepared, _, err := hub.PrepareMappedFD("pin", "/nonexistent/worker-has-no-path-access", false, nil, nil, root)
	if err != nil {
		t.Fatalf("pinned export must not resolve the root path: %v", err)
	}
	if _, err := hub.Publish(prepared); err != nil {
		t.Fatal(err)
	}
	rootNode, errno := hubLookup(t, hub, 2, 1, "pin")
	if errno != 0 {
		t.Fatalf("root lookup errno %d", errno)
	}
	fileNode, errno := hubLookup(t, hub, 3, rootNode, "file.txt")
	if errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}
	openIn := make([]byte, 8) // O_RDONLY
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseOpen, 4, fileNode, len(openIn)), openIn},
		16, 16); errno != 0 {
		t.Errorf("open regular file through pinned export errno %d, want 0", errno)
	}
	// The special-file policy must be enforced fd-relative: under
	// confinement an absolute Lstat silently fails open.
	pipeNode, errno := hubLookup(t, hub, 5, rootNode, "pipe")
	if errno != 0 {
		t.Fatalf("fifo lookup errno %d", errno)
	}
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseOpen, 6, pipeNode, len(openIn)), openIn},
		16, 16); errno != -1 { // EPERM
		t.Errorf("open FIFO through pinned export errno %d, want EPERM", errno)
	}
}
