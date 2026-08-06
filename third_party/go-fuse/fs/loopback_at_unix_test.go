//go:build linux || darwin

package fs

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestOpenRelDirRootHasIndependentOffsets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/visible", []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}

	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	for attempt := 0; attempt < 2; attempt++ {
		fd, err := openRelDir(int(root.Fd()), "")
		if err != nil {
			t.Fatalf("open root attempt %d: %v", attempt+1, err)
		}
		ds, errno := NewLoopbackDirStreamFd(fd)
		if errno != 0 {
			t.Fatalf("dir stream attempt %d: %v", attempt+1, errno)
		}

		found := false
		for ds.HasNext() {
			entry, errno := ds.Next()
			if errno != 0 {
				ds.Close()
				t.Fatalf("read attempt %d: %v", attempt+1, errno)
			}
			if entry.Name == "visible" {
				found = true
			}
		}
		ds.Close()
		if !found {
			t.Fatalf("attempt %d did not see root entry", attempt+1)
		}
	}
}

// openRelDir must refuse a FIFO intermediate component immediately:
// O_DIRECTORY makes the kernel fail the open with ENOTDIR instead of
// blocking in open(O_RDONLY) until a writer appears (guest-reachable DoS
// via a crafted parent inode; the Fstat S_IFDIR check used to run only
// AFTER the blocking open).
func TestOpenRelDirRejectsFIFOComponent(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(dir+"/pipe", 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	type result struct {
		fd  int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		fd, err := openRelDir(int(root.Fd()), "pipe/child")
		ch <- result{fd, err}
	}()
	select {
	case r := <-ch:
		if r.fd >= 0 {
			syscall.Close(r.fd)
			t.Fatal("openRelDir succeeded through a FIFO component")
		}
		if !errors.Is(r.err, syscall.ENOTDIR) {
			t.Fatalf("want ENOTDIR, got %v", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("openRelDir blocked on a FIFO intermediate component")
	}
}

// Same guarantee for the export root's own descriptor path and for deeper
// traversal: a real directory chain still opens, a FIFO at the END of the
// chain is rejected too.
func TestOpenRelDirTraversalFlags(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir+"/a/b", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(dir+"/a/b/pipe", 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	fd, err := openRelDir(int(root.Fd()), "a/b")
	if err != nil {
		t.Fatalf("directory chain: %v", err)
	}
	syscall.Close(fd)

	if fd, err := openRelDir(int(root.Fd()), "a/b/pipe"); err == nil {
		syscall.Close(fd)
		t.Fatal("FIFO final component opened as a directory")
	} else if !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("want ENOTDIR, got %v", err)
	}
}
