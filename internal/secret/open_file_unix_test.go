//go:build !windows

package secret

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFileSourceRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(nil, nil)
	store.Put("TOKEN", Source{Kind: SourceFile, Ref: path})
	started := time.Now()
	_, err := store.Resolve("TOKEN")
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("FIFO resolution error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("FIFO resolution blocked for %s", elapsed)
	}
}
