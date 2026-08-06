//go:build linux || darwin

package fs

import (
	"os"
	"testing"
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
