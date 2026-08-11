//go:build linux || darwin

package sharefs

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/fusewire"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func fuseInitHubMinor(t *testing.T, hub *Hub, minor uint32) {
	t.Helper()
	payload := make([]byte, 64)
	binary.LittleEndian.PutUint32(payload[0:4], 7)
	binary.LittleEndian.PutUint32(payload[4:8], minor)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseInit, 1, 0, len(payload)), payload}, 16, 64); errno != 0 {
		t.Fatalf("FUSE_INIT errno %d", errno)
	}
}

func notificationCode(message []byte) int32 {
	return int32(binary.LittleEndian.Uint32(message[4:8]))
}

func TestWatcherHealthyMetadataTTLAndInvalidations(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "after-loss"), []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()

	notifications := make(chan []byte, 32)
	hub.SetNotificationSink(func(message []byte) fuse.Status {
		if !fusewire.ValidNotification(message) {
			return fuse.EINVAL
		}
		notifications <- append([]byte(nil), message...)
		return fuse.OK
	})
	fuseInitHubMinor(t, hub, 45)
	export := publishHubShare(t, hub, "workspace", root, false)
	if export.coherence == nil || !export.coherence.Healthy() {
		t.Skip("native recursive watcher unavailable")
	}
	exportNode, errno := hubLookup(t, hub, 2, 1, "workspace")
	if errno != 0 {
		t.Fatalf("export lookup errno %d", errno)
	}
	if _, errno := hubLookup(t, hub, 3, exportNode, "file"); errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}

	var cached fuse.EntryOut
	if _, errno := export.inode.Operations().(*shareNode).Lookup(t.Context(), "file", &cached); errno != 0 {
		t.Fatalf("cached lookup: %v", errno)
	}
	if cached.EntryTimeout() != watchedMetadataTTL || cached.AttrTimeout() != watchedMetadataTTL {
		t.Fatalf("healthy TTL = %s/%s, want %s", cached.EntryTimeout(), cached.AttrTimeout(), watchedMetadataTTL)
	}

	export.coherence.handleWatchEvent(shareWatchEvent{rel: "file"})
	codes := map[int32]bool{}
	for len(codes) < 2 {
		select {
		case message := <-notifications:
			codes[notificationCode(message)] = true
		case <-time.After(time.Second):
			t.Fatalf("notifications = %v, want INVAL_ENTRY and INVAL_INODE", codes)
		}
	}
	if !codes[fuse.NOTIFY_INVAL_ENTRY] || !codes[fuse.NOTIFY_INVAL_INODE] {
		t.Fatalf("notification codes = %v", codes)
	}

	export.coherence.handleWatchEvent(shareWatchEvent{loss: os.ErrDeadlineExceeded})
	foundEpoch := false
	deadline := time.After(time.Second)
	for !foundEpoch {
		select {
		case message := <-notifications:
			foundEpoch = notificationCode(message) == fuse.NOTIFY_INC_EPOCH
		case <-deadline:
			t.Fatal("watcher loss did not emit INC_EPOCH")
		}
	}
	if export.coherence.Healthy() {
		t.Fatal("watcher remained healthy after continuity loss")
	}
	var fallback fuse.EntryOut
	if _, errno := export.inode.Operations().(*shareNode).Lookup(t.Context(), "after-loss", &fallback); errno != 0 {
		t.Fatalf("fallback lookup: %v", errno)
	}
	if fallback.EntryTimeout() != descendantMetadataTTL || fallback.AttrTimeout() != descendantMetadataTTL {
		t.Fatalf("fallback TTL = %s/%s, want %s", fallback.EntryTimeout(), fallback.AttrTimeout(), descendantMetadataTTL)
	}
}
