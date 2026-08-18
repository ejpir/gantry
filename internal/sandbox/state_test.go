package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/boundedlog"
)

func TestReadFileTailDoesNotReadSparsePrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-huge.log")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	const sparseSize = int64(1 << 30)
	if err := file.Truncate(sparseSize); err != nil {
		t.Fatal(err)
	}
	marker := []byte("bounded-tail-marker")
	if _, err := file.WriteAt(marker, sparseSize-int64(len(marker))); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	tail, err := boundedlog.ReadTail(path, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 4096 {
		t.Fatalf("tail length = %d, want 4096", len(tail))
	}
	if !bytes.HasSuffix(tail, marker) {
		t.Fatalf("tail does not end in marker: %q", tail[len(tail)-64:])
	}
}
