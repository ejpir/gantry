//go:build linux

package sharefs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func waitNotificationCode(t *testing.T, notifications <-chan []byte, status int32) {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case message := <-notifications:
			// go-fuse exposes notifications as negative Status values, while
			// fuse_out_header.error contains the positive enum on the wire.
			if notificationCode(message) == -status {
				return
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for FUSE notification %d", -status)
		}
	}
}

func drainNotifications(notifications <-chan []byte) {
	for {
		select {
		case <-notifications:
		default:
			return
		}
	}
}

func TestLinuxWatcherObservesExternalHostMutations(t *testing.T) {
	root := t.TempDir()
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	notifications := make(chan []byte, 64)
	hub.SetNotificationSink(func(message []byte) fuse.Status {
		notifications <- append([]byte(nil), message...)
		return fuse.OK
	})
	fuseInitHubMinor(t, hub, 45)
	export := publishHubShare(t, hub, "workspace", root, false)
	if export.coherence == nil || !export.coherence.Healthy() {
		t.Fatalf("inotify watcher did not start: %v", export.coherence.watchErr)
	}
	exportNode, errno := hubLookup(t, hub, 2, 1, "workspace")
	if errno != 0 {
		t.Fatalf("export lookup errno %d", errno)
	}
	drainNotifications(notifications)

	hostFile := filepath.Join(root, "external")
	if err := os.WriteFile(hostFile, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitNotificationCode(t, notifications, fuse.NOTIFY_INVAL_ENTRY)
	if _, errno := hubLookup(t, hub, 3, exportNode, "external"); errno != 0 {
		t.Fatalf("external lookup errno %d", errno)
	}
	drainNotifications(notifications)

	renamed := filepath.Join(root, "renamed")
	if err := os.Rename(hostFile, renamed); err != nil {
		t.Fatal(err)
	}
	waitNotificationCode(t, notifications, fuse.NOTIFY_INVAL_ENTRY)
	waitNotificationCode(t, notifications, fuse.NOTIFY_INC_EPOCH)
	if !export.coherence.Healthy() {
		t.Fatal("ordinary rename degraded watcher health")
	}
	if _, errno := hubLookup(t, hub, 4, exportNode, "renamed"); errno != 0 {
		t.Fatalf("renamed lookup errno %d", errno)
	}
	hostFile = renamed
	drainNotifications(notifications)

	if err := os.WriteFile(hostFile, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitNotificationCode(t, notifications, fuse.NOTIFY_INVAL_INODE)
	drainNotifications(notifications)

	if err := os.Remove(hostFile); err != nil {
		t.Fatal(err)
	}
	waitNotificationCode(t, notifications, fuse.NOTIFY_INVAL_ENTRY)
	drainNotifications(notifications)

	hostDir := filepath.Join(root, "external-dir")
	if err := os.Mkdir(hostDir, 0o700); err != nil {
		t.Fatal(err)
	}
	waitNotificationCode(t, notifications, fuse.NOTIFY_INVAL_ENTRY)
	if _, errno := hubLookup(t, hub, 5, exportNode, "external-dir"); errno != 0 {
		t.Fatalf("external directory lookup errno %d", errno)
	}
	drainNotifications(notifications)
	if err := os.Remove(hostDir); err != nil {
		t.Fatal(err)
	}
	waitNotificationCode(t, notifications, fuse.NOTIFY_INVAL_ENTRY)
	if !export.coherence.Healthy() {
		t.Fatal("ordinary watched-directory deletion degraded watcher health")
	}
}
