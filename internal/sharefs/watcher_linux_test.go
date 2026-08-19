//go:build linux

package sharefs

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

func linuxInotifyRecord(wd int32, mask, cookie uint32, name string) []byte {
	nameLen := (len(name) + 1 + 3) &^ 3
	record := make([]byte, unix.SizeofInotifyEvent+nameLen)
	binary.LittleEndian.PutUint32(record[0:4], uint32(wd))
	binary.LittleEndian.PutUint32(record[4:8], mask)
	binary.LittleEndian.PutUint32(record[8:12], cookie)
	binary.LittleEndian.PutUint32(record[12:16], uint32(nameLen))
	copy(record[unix.SizeofInotifyEvent:], name)
	return record
}

func TestLinuxWatcherPairsRenameAcrossReadBuffers(t *testing.T) {
	var events []shareWatchEvent
	w := &linuxShareWatcher{
		byWD:         map[int]string{1: "left", 2: "right"},
		byPath:       map[string]int{"left": 1, "right": 2},
		pendingMoves: make(map[uint32]linuxPendingMove),
		emit:         func(event shareWatchEvent) { events = append(events, event) },
	}

	w.process(linuxInotifyRecord(1, unix.IN_MOVED_FROM, 42, "old"))
	if len(events) != 0 {
		t.Fatalf("source half emitted before its pair: %+v", events)
	}
	w.process(linuxInotifyRecord(2, unix.IN_MOVED_TO, 42, "new"))
	want := []shareWatchEvent{{rel: "left/old", relTo: "right/new", rename: true}}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("rename events = %+v, want %+v", events, want)
	}
	if len(w.pendingMoves) != 0 {
		t.Fatalf("paired rename left pending state: %+v", w.pendingMoves)
	}
}

func TestLinuxWatcherFlushesUnpairedRenameDuringActiveTraffic(t *testing.T) {
	var events []shareWatchEvent
	w := &linuxShareWatcher{
		byWD:         map[int]string{1: "left"},
		byPath:       map[string]int{"left": 1},
		pendingMoves: make(map[uint32]linuxPendingMove),
		emit:         func(event shareWatchEvent) { events = append(events, event) },
	}

	w.process(linuxInotifyRecord(1, unix.IN_MOVED_FROM, 7, "gone"))
	pending := w.pendingMoves[7]
	pending.deadline = time.Now().Add(-time.Millisecond)
	w.pendingMoves[7] = pending
	w.process(linuxInotifyRecord(1, unix.IN_MODIFY, 0, "busy"))
	want := []shareWatchEvent{
		{rel: "left/busy"},
		{rel: "left/gone", rename: true},
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("unpaired rename events = %+v, want %+v", events, want)
	}
}

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
