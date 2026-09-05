//go:build linux || darwin

package control

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sharefs"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func managerFuseHeader(op uint32, unique, nodeID uint64, payloadLen int) []byte {
	header := make([]byte, 40)
	binary.LittleEndian.PutUint32(header[0:4], uint32(len(header)+payloadLen))
	binary.LittleEndian.PutUint32(header[4:8], op)
	binary.LittleEndian.PutUint64(header[8:16], unique)
	binary.LittleEndian.PutUint64(header[16:24], nodeID)
	return header
}

func managerFuseRequest(t *testing.T, hub *sharefs.Hub, in [][]byte, payloadSize int) [][]byte {
	t.Helper()
	out := [][]byte{make([]byte, 16), make([]byte, payloadSize)}
	if _, status := hub.HandleRequest(in, out); status != fuse.OK {
		t.Fatalf("FUSE transport status %v", status)
	}
	if errno := int32(binary.LittleEndian.Uint32(out[0][4:8])); errno != 0 {
		t.Fatalf("FUSE errno %d", errno)
	}
	return out
}

func retainManagerShareRoot(t *testing.T, hub *sharefs.Hub, tag string) {
	t.Helper()
	init := make([]byte, 64)
	binary.LittleEndian.PutUint32(init[0:4], 7)
	binary.LittleEndian.PutUint32(init[4:8], 38)
	managerFuseRequest(t, hub, [][]byte{managerFuseHeader(26, 1, 0, len(init)), init}, 64)
	name := append([]byte(tag), 0)
	out := managerFuseRequest(t, hub, [][]byte{managerFuseHeader(1, 2, 1, len(name)), name}, 128)
	if nodeID := binary.LittleEndian.Uint64(out[1][0:8]); nodeID == 0 {
		t.Fatal("share lookup returned a zero node ID")
	}
}

func TestShareManagerRejectsOverlapWithDrainingExport(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	manager, _ := newTestShareManager(t, "code="+root)
	retainManagerShareRoot(t, manager.Hub(), "code")
	removed, err := manager.Remove("code", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if removed.State != "draining" {
		t.Fatalf("removed share state = %q, want draining", removed.State)
	}

	for _, spec := range []string{"alias=" + root, "child=" + child} {
		if _, err := manager.Add(spec, false, false); err == nil || !strings.Contains(err.Error(), "draining share") {
			t.Fatalf("Add(%q) error = %v, want draining overlap rejection", spec, err)
		}
	}
	if _, err := manager.Add("other="+t.TempDir(), false, false); err != nil {
		t.Fatalf("non-overlapping add failed: %v", err)
	}
}
