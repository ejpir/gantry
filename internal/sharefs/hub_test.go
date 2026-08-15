//go:build linux || darwin || windows

package sharefs

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/fusewire"
	"github.com/ejpir/gantry/internal/sharebroker"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

const (
	fuseLookup      = 1
	fuseSetattr     = 4
	fuseSymlink     = 6
	fuseUnlink      = 10
	fuseOpen        = 14
	fuseRead        = 15
	fuseWrite       = 16
	fuseInit        = 26
	fuseCreate      = 35
	fuseGetattr     = 3
	fuseReadlink    = 5
	fuseGetxattr    = 22
	fuseOpendir     = 27
	fuseReaddirplus = 44
	fuseListxattr   = 23
	fuseSetxattr    = 21
	fuseRemovexattr = 24
	fuseStatx       = 52
	linuxENOSYS     = 38
)

func TestShareHubReadlinkUsesResponsePayloadCapacity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows shares do not expose host symlinks")
	}
	root := t.TempDir()
	target := "some/relative/target"
	if err := os.Symlink(target, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	fuseInitHub(t, hub)
	publishHubShare(t, hub, "work", root, false)
	tagNode, errno := hubLookup(t, hub, 2, 1, "work")
	if errno != 0 {
		t.Fatalf("share lookup errno %d", errno)
	}
	linkNode, errno := hubLookup(t, hub, 3, tagNode, "link")
	if errno != 0 {
		t.Fatalf("symlink lookup errno %d", errno)
	}

	n, errno, out := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseReadlink, 4, linkNode, 0)}, 16, 3, 61)
	if errno != 0 {
		t.Fatalf("READLINK errno %d", errno)
	}
	if want := 16 + len(target); n != want {
		t.Fatalf("READLINK response size = %d, want %d", n, want)
	}
	if got := string(bytes.Join(out[1:], nil)[:len(target)]); got != target {
		t.Fatalf("READLINK target = %q, want %q", got, target)
	}
}

type resourceLimitHandler struct {
	nodes, handles int
	calls          int
	prunes         int
	pruneStatus    fuse.Status
}

func TestShareHubSetattrDoesNotFollowFinalSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix chmod boundary")
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	fuseInitHub(t, hub)
	publishHubShare(t, hub, "work", root, false)
	tagNode, errno := hubLookup(t, hub, 2, 1, "work")
	if errno != 0 {
		t.Fatalf("share lookup errno %d", errno)
	}
	linkNode, errno := hubLookup(t, hub, 3, tagNode, "link")
	if errno != 0 {
		t.Fatalf("symlink lookup errno %d", errno)
	}
	// fuse_setattr_in after the 40-byte header: valid is at 0, mode at 68.
	setattr := make([]byte, 88)
	binary.LittleEndian.PutUint32(setattr[0:4], fuse.FATTR_MODE)
	binary.LittleEndian.PutUint32(setattr[68:72], 0o777)
	fileNode, errno := hubLookup(t, hub, 4, tagNode, "file")
	if errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseSetattr, 5, fileNode, len(setattr)), setattr}, 16, 104); errno != 0 {
		t.Fatalf("SETATTR mode on regular file errno %d", errno)
	}
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseSetattr, 6, linkNode, len(setattr)), setattr}, 16, 104); errno == 0 {
		t.Fatal("SETATTR mode unexpectedly succeeded on a symlink")
	}
	info, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("outside target mode = %o, want 600", got)
	}
}

func (h *resourceLimitHandler) HandleRequest(_, _ [][]byte) (int, fuse.Status) {
	h.calls++
	return 7, fuse.OK
}

func (h *resourceLimitHandler) GantryResourceUsage() (nodes, handles int) {
	return h.nodes, h.handles
}

func (h *resourceLimitHandler) GantryPruneResources(int) fuse.Status {
	h.prunes++
	return h.pruneStatus
}

func TestShareRequestGuardBackpressuresWithoutPoisoningShare(t *testing.T) {
	handler := &resourceLimitHandler{nodes: maxLiveNodes + 1, handles: shareHandleLimit() + 1}
	guard := newRequestGuard()
	guard.setReporter(handler)
	lookup := [][]byte{fuseInHeader(fuseLookup, 1, 1, 0)}
	if n, status := guard.handle(handler, lookup, nil); n != 0 || status != fuse.EAGAIN {
		t.Fatalf("node-pressure response = %d/%v, want 0/EAGAIN", n, status)
	}
	open := [][]byte{fuseInHeader(fuseOpen, 2, 1, 0)}
	if n, status := guard.handle(handler, open, nil); n != 0 || status != fuse.EMFILE {
		t.Fatalf("handle-pressure response = %d/%v, want 0/EMFILE", n, status)
	}
	// Existing-node operations and cleanup remain available under pressure.
	readlink := [][]byte{fuseInHeader(fuseReadlink, 3, 1, 0)}
	if n, status := guard.handle(handler, readlink, nil); n != 7 || status != fuse.OK {
		t.Fatalf("READLINK under pressure = %d/%v, want 7/OK", n, status)
	}
	handler.nodes, handler.handles = 0, 0
	if n, status := guard.handle(handler, lookup, nil); n != 7 || status != fuse.OK {
		t.Fatalf("recovered response = %d/%v, want 7/OK", n, status)
	}
	if handler.calls != 2 {
		t.Fatalf("handler invoked %d times, want 2", handler.calls)
	}
}

func TestShareRequestGuardPrunesBeforeNodeWatermark(t *testing.T) {
	handler := &resourceLimitHandler{nodes: pruneNodeMark}
	guard := newRequestGuard()
	guard.setReporter(handler)
	getattr := [][]byte{fuseInHeader(fuseGetattr, 1, 1, 0)}
	if _, status := guard.handle(handler, getattr, nil); status != fuse.OK {
		t.Fatal(status)
	}
	if handler.prunes != 1 {
		t.Fatalf("prune calls = %d, want 1", handler.prunes)
	}
	if _, status := guard.handle(handler, getattr, nil); status != fuse.OK {
		t.Fatal(status)
	}
	if handler.prunes != 1 {
		t.Fatalf("unchanged usage caused %d prune calls, want 1", handler.prunes)
	}
	handler.nodes += resourcePruneSize
	if _, status := guard.handle(handler, getattr, nil); status != fuse.OK {
		t.Fatal(status)
	}
	if handler.prunes != 2 {
		t.Fatalf("grown usage caused %d prune calls, want 2", handler.prunes)
	}
}

func TestShareRequestGuardAllowsBoundedPruneHeadroom(t *testing.T) {
	handler := &resourceLimitHandler{nodes: nodePruneWatermark}
	guard := newRequestGuard()
	guard.setReporter(handler)
	lookup := [][]byte{fuseInHeader(fuseLookup, 1, 1, 0)}
	if n, status := guard.handle(handler, lookup, nil); n != 7 || status != fuse.OK {
		t.Fatalf("lookup in prune headroom = %d/%v, want 7/OK", n, status)
	}
	if handler.prunes == 0 {
		t.Fatal("lookup in prune headroom did not request reclamation")
	}

	handler.nodes = maxLiveNodes
	if n, status := guard.handle(handler, lookup, nil); n != 0 || status != fuse.EAGAIN {
		t.Fatalf("lookup at hard limit = %d/%v, want 0/EAGAIN", n, status)
	}
}

func TestShareHubPrunesRetainedNodes(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	payload := make([]byte, 64)
	binary.LittleEndian.PutUint32(payload[0:4], 7)
	binary.LittleEndian.PutUint32(payload[4:8], 45)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseInit, 1, 0, len(payload)), payload}, 16, 64); errno != 0 {
		t.Fatalf("FUSE_INIT errno %d", errno)
	}
	publishHubShare(t, hub, "work", t.TempDir(), false)
	if _, errno := hubLookup(t, hub, 2, 1, "work"); errno != 0 {
		t.Fatalf("share lookup errno %d", errno)
	}

	notifications := make(chan []byte, 1)
	hub.SetNotificationSink(func(message []byte) fuse.Status {
		notifications <- append([]byte(nil), message...)
		return fuse.OK
	})
	if status := hub.protocol.GantryPruneResources(10); status != fuse.OK {
		t.Fatalf("prune status = %v", status)
	}
	message := <-notifications
	if !fusewire.ValidNotification(message) {
		t.Fatalf("invalid prune notification: %x", message)
	}
	wantCode := int32(-fuse.NOTIFY_PRUNE)
	if code := int32(binary.LittleEndian.Uint32(message[4:8])); code != wantCode {
		t.Fatalf("notification code = %d, want %d", code, wantCode)
	}
	count := binary.LittleEndian.Uint32(message[16:20])
	if count == 0 || len(message) != 32+int(count)*8 {
		t.Fatalf("prune count/size = %d/%d", count, len(message))
	}
}

func fuseInHeader(op uint32, unique, nodeid uint64, payloadLen int) []byte {
	b := make([]byte, 40)
	binary.LittleEndian.PutUint32(b[0:4], uint32(40+payloadLen))
	binary.LittleEndian.PutUint32(b[4:8], op)
	binary.LittleEndian.PutUint64(b[8:16], unique)
	binary.LittleEndian.PutUint64(b[16:24], nodeid)
	return b
}

func fuseInitHub(t *testing.T, hub *Hub) {
	t.Helper()
	payload := make([]byte, 64)
	binary.LittleEndian.PutUint32(payload[0:4], 7)
	binary.LittleEndian.PutUint32(payload[4:8], 38)
	capabilities := uint64(fuse.CAP_INIT_EXT | fuse.CAP_GANTRY_READDIR_EOF)
	binary.LittleEndian.PutUint32(payload[12:16], uint32(capabilities))
	binary.LittleEndian.PutUint32(payload[16:20], uint32(capabilities>>32))
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseInit, 1, 0, len(payload)), payload}, 16, 64); errno != 0 {
		t.Fatalf("FUSE_INIT errno %d", errno)
	}
}

func hubReq(t *testing.T, hub *Hub, in [][]byte, outSizes ...int) (int, int32, [][]byte) {
	return handlerReq(t, hub, in, outSizes...)
}

func handlerReq(t *testing.T, handler fusewire.Handler, in [][]byte, outSizes ...int) (int, int32, [][]byte) {
	t.Helper()
	out := make([][]byte, len(outSizes))
	for i, n := range outSizes {
		out[i] = make([]byte, n)
	}
	n, status := handler.HandleRequest(in, out)
	if status != fuse.OK {
		t.Fatalf("transport status %v", status)
	}
	errno := int32(binary.LittleEndian.Uint32(out[0][4:8]))
	return n, errno, out
}

func TestShareHubNegotiatesAdaptiveReadDirPlus(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	payload := make([]byte, 64)
	binary.LittleEndian.PutUint32(payload[0:4], 7)
	binary.LittleEndian.PutUint32(payload[4:8], 38)
	capabilities := uint64(fuse.CAP_READDIRPLUS | fuse.CAP_READDIRPLUS_AUTO | fuse.CAP_NO_OPENDIR_SUPPORT |
		fuse.CAP_INIT_EXT | fuse.CAP_GANTRY_READDIR_EOF)
	binary.LittleEndian.PutUint32(payload[12:16], uint32(capabilities))
	binary.LittleEndian.PutUint32(payload[16:20], uint32(capabilities>>32))
	_, errno, out := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseInit, 1, 0, len(payload)), payload}, 16, 64)
	if errno != 0 {
		t.Fatalf("FUSE_INIT errno %d", errno)
	}
	flags := uint64(binary.LittleEndian.Uint32(out[1][12:16])) |
		uint64(binary.LittleEndian.Uint32(out[1][32:36]))<<32
	want := uint64(fuse.CAP_READDIRPLUS | fuse.CAP_READDIRPLUS_AUTO | fuse.CAP_GANTRY_READDIR_EOF)
	if runtime.GOOS != "windows" {
		want |= fuse.CAP_NO_OPENDIR_SUPPORT
	}
	if flags&want != want {
		t.Fatalf("FUSE_INIT flags %#x, want adaptive READDIRPLUS and Gantry EOF %#x", flags, want)
	}
	if runtime.GOOS == "windows" && flags&fuse.CAP_NO_OPENDIR_SUPPORT != 0 {
		t.Fatalf("FUSE_INIT flags %#x unexpectedly enabled zero-message OPENDIR on Windows", flags)
	}
}

func TestShareHubReadDirPlusOnlyPrefetchesDirectories(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "directory"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "regular"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	fuseInitHub(t, hub)
	publishHubShare(t, hub, "tree", root, true)
	treeNode, errno := hubLookup(t, hub, 2, 1, "tree")
	if errno != 0 {
		t.Fatalf("tree lookup errno %d", errno)
	}
	opendirIn := make([]byte, 8)
	_, errno, openOut := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseOpendir, 3, treeNode, len(opendirIn)), opendirIn}, 16, 16)
	var dirHandle uint64
	if runtime.GOOS == "windows" {
		if errno != 0 {
			t.Fatalf("Windows persistent opendir errno %d", errno)
		}
		dirHandle = binary.LittleEndian.Uint64(openOut[1][:8])
	} else if errno != -linuxENOSYS {
		t.Fatalf("opendir errno %d, want Linux ENOSYS for zero-message mode", errno)
	}
	readIn := make([]byte, 40)
	binary.LittleEndian.PutUint64(readIn[0:8], dirHandle)
	binary.LittleEndian.PutUint32(readIn[16:20], 4096)
	n, errno, readOut := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseReaddirplus, 4, treeNode, len(readIn)), readIn}, 16, 4096)
	if errno != 0 {
		t.Fatalf("readdirplus errno %d", errno)
	}
	if n < 16 || n-16 > len(readOut[1]) {
		t.Fatalf("readdirplus response length %d", n)
	}
	const entryOutSize = 128
	entries := make(map[string]uint64)
	sawEOF := false
	payload := readOut[1][:n-16]
	for len(payload) != 0 {
		if len(payload) < entryOutSize+24 {
			t.Fatalf("short dirent-plus record: %d bytes", len(payload))
		}
		dirent := payload[entryOutSize:]
		nameLength := int(binary.LittleEndian.Uint32(dirent[16:20]))
		if nameLength == 0 && binary.LittleEndian.Uint64(dirent[0:8]) == fuse.GANTRY_READDIR_EOF_INO &&
			binary.LittleEndian.Uint64(dirent[8:16]) == fuse.GANTRY_READDIR_EOF_OFF &&
			binary.LittleEndian.Uint32(dirent[20:24]) == fuse.GANTRY_READDIR_EOF_TYPE {
			sawEOF = true
			payload = payload[entryOutSize+24:]
			if len(payload) != 0 {
				t.Fatalf("%d bytes follow READDIRPLUS EOF marker", len(payload))
			}
			break
		}
		recordLength := (entryOutSize + 24 + nameLength + 7) &^ 7
		if nameLength < 0 || recordLength > len(payload) {
			t.Fatalf("invalid dirent-plus name/record length %d/%d", nameLength, len(payload))
		}
		name := string(dirent[24 : 24+nameLength])
		entries[name] = binary.LittleEndian.Uint64(payload[0:8])
		payload = payload[recordLength:]
	}
	if entries["directory"] == 0 {
		t.Fatal("directory READDIRPLUS entry has no prefetched node")
	}
	if entries["regular"] != 0 {
		t.Fatalf("regular READDIRPLUS entry eagerly instantiated node %d", entries["regular"])
	}
	if !sawEOF {
		t.Fatal("negotiated READDIRPLUS response omitted EOF marker")
	}
}

func TestShareHubBrokeredReadOnlyPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("brokered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	prepared, _, err := hub.Prepare("docs", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hub.Publish(prepared); err != nil {
		t.Fatal(err)
	}

	server, transport := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- sharebroker.Serve(server, hub) }()
	client, err := sharebroker.NewClient(transport)
	if err != nil {
		t.Fatal(err)
	}

	initPayload := make([]byte, 64)
	binary.LittleEndian.PutUint32(initPayload[0:4], 7)
	binary.LittleEndian.PutUint32(initPayload[4:8], 38)
	if _, errno, _ := handlerReq(t, client,
		[][]byte{fuseInHeader(fuseInit, 1, 0, len(initPayload)), initPayload}, 16, 64); errno != 0 {
		t.Fatalf("FUSE_INIT errno %d", errno)
	}
	tagNode, errno := handlerLookup(t, client, 2, 1, "docs")
	if errno != 0 {
		t.Fatalf("share lookup errno %d", errno)
	}
	fileNode, errno := handlerLookup(t, client, 3, tagNode, "hello.txt")
	if errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}
	open := make([]byte, 8)
	binary.LittleEndian.PutUint32(open[0:4], 1) // Linux O_WRONLY on the wire.
	if _, errno, _ := handlerReq(t, client,
		[][]byte{fuseInHeader(fuseOpen, 4, fileNode, len(open)), open}, 16, 16); errno != -30 {
		t.Fatalf("writable open on read-only export errno %d, want EROFS", errno)
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("share broker shutdown: %v", err)
	}
}

func handlerLookup(t *testing.T, handler fusewire.Handler, unique, parent uint64, name string) (uint64, int32) {
	t.Helper()
	wireName := append([]byte(name), 0)
	_, errno, out := handlerReq(t, handler,
		[][]byte{fuseInHeader(fuseLookup, unique, parent, len(wireName)), wireName}, 16, 128)
	if errno != 0 {
		return 0, errno
	}
	return binary.LittleEndian.Uint64(out[1][0:8]), 0
}

func hubLookup(t *testing.T, hub *Hub, unique uint64, parent uint64, name string) (uint64, int32) {
	t.Helper()
	wireName := append([]byte(name), 0)
	_, errno, out := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseLookup, unique, parent, len(wireName)), wireName}, 16, 128)
	if errno != 0 {
		return 0, errno
	}
	return binary.LittleEndian.Uint64(out[1][0:8]), 0
}

func publishHubShare(t testing.TB, hub *Hub, tag, path string, ro bool) *Export {
	t.Helper()
	prepared, _, err := hub.Prepare(tag, path, ro)
	if err != nil {
		t.Fatal(err)
	}
	export, err := hub.Publish(prepared)
	if err != nil {
		t.Fatal(err)
	}
	return export
}

func TestShareHubPublishConsumesPreparedExport(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	prepared, _, err := hub.Prepare("workspace", t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	export, err := hub.Publish(prepared)
	if err != nil {
		t.Fatal(err)
	}
	prepared.Close()
	if export.State() != ExportActive {
		t.Fatalf("closing consumed preparation changed live export to %s", export.State())
	}
	if _, err := hub.Publish(prepared); err == nil {
		t.Fatal("published preparation was reusable")
	}
}

func TestShareHubCachesOnlyExportDescendants(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	publishHubShare(t, hub, "workspace", dir, false)

	var exportOut fuse.EntryOut
	exportRoot, errno := hub.root.Lookup(context.Background(), "workspace", &exportOut)
	if errno != 0 {
		t.Fatalf("export lookup: %v", errno)
	}
	if exportOut.EntryTimeout() != 0 || exportOut.AttrTimeout() != 0 {
		t.Fatalf("dynamic export entry cached: entry=%s attr=%s", exportOut.EntryTimeout(), exportOut.AttrTimeout())
	}

	var childOut fuse.EntryOut
	if _, errno := exportRoot.Operations().(fs.NodeLookuper).Lookup(context.Background(), "sub", &childOut); errno != 0 {
		t.Fatalf("descendant lookup: %v", errno)
	}
	if childOut.EntryTimeout() != descendantMetadataTTL || childOut.AttrTimeout() != descendantMetadataTTL {
		t.Fatalf("descendant timeout = entry %s attr %s, want %s", childOut.EntryTimeout(), childOut.AttrTimeout(), descendantMetadataTTL)
	}

	var missing fuse.EntryOut
	if _, errno := exportRoot.Operations().(fs.NodeLookuper).Lookup(context.Background(), "missing", &missing); fuse.ToStatus(errno) != fuse.ENOENT {
		t.Fatalf("missing lookup errno = %v, want ENOENT", errno)
	}
	if missing.EntryTimeout() != 0 {
		t.Fatalf("negative entry cached for %s", missing.EntryTimeout())
	}
}

func TestShareHubMapsGuestOwnership(t *testing.T) {
	if !shareOwnerMappingSupported {
		t.Skip("ownership mapping is not supported on this platform")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	uid, gid := uint32(1000), uint32(1000)
	prepared, _, err := hub.PrepareMapped("workspace", dir, false, &uid, &gid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hub.Publish(prepared); err != nil {
		t.Fatal(err)
	}
	var rootOut fuse.EntryOut
	root, errno := hub.root.Lookup(context.Background(), "workspace", &rootOut)
	if errno != 0 {
		t.Fatalf("root lookup: %v", errno)
	}
	if rootOut.Uid != uid || rootOut.Gid != gid {
		t.Fatalf("root owner = %d:%d, want %d:%d", rootOut.Uid, rootOut.Gid, uid, gid)
	}
	var fileOut fuse.EntryOut
	lookup := root.Operations().(fs.NodeLookuper)
	if _, errno := lookup.Lookup(context.Background(), "file", &fileOut); errno != 0 {
		t.Fatalf("file lookup: %v", errno)
	}
	if fileOut.Uid != uid || fileOut.Gid != gid {
		t.Fatalf("file owner = %d:%d, want %d:%d", fileOut.Uid, fileOut.Gid, uid, gid)
	}
}

func TestShareHubStatxMapsGuestOwnership(t *testing.T) {
	if !shareOwnerMappingSupported {
		t.Skip("ownership mapping is not supported on this platform")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	fuseInitHub(t, hub)

	uid, gid := uint32(1000), uint32(1001)
	prepared, _, err := hub.PrepareMapped("workspace", dir, false, &uid, &gid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hub.Publish(prepared); err != nil {
		t.Fatal(err)
	}
	rootNode, errno := hubLookup(t, hub, 2, 1, "workspace")
	if errno != 0 {
		t.Fatalf("root lookup errno %d", errno)
	}
	fileNode, errno := hubLookup(t, hub, 3, rootNode, "file")
	if errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}

	statxIn := make([]byte, 24)
	binary.LittleEndian.PutUint32(statxIn[20:24], 0x07ff)
	_, errno, statxOut := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseStatx, 4, fileNode, len(statxIn)), statxIn}, 16, 288)
	if errno != 0 {
		t.Fatalf("statx errno %d", errno)
	}
	if gotUID, gotGID := binary.LittleEndian.Uint32(statxOut[1][52:56]), binary.LittleEndian.Uint32(statxOut[1][56:60]); gotUID != uid || gotGID != gid {
		t.Fatalf("statx owner = %d:%d, want %d:%d", gotUID, gotGID, uid, gid)
	}
}

func TestShareHubDynamicNamespace(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	fuseInitHub(t, hub)

	const (
		erofs  = -30
		estale = -116
	)
	if node, errno := hubLookup(t, hub, 2, 1, "code"); node != 0 || errno != 0 {
		t.Fatalf("missing dynamic share lookup node=%d errno=%d, want negative node 0", node, errno)
	}

	dir := t.TempDir()
	// testing.TempDir creates its numbered child with 0777 and the process
	// umask. Pin the mode this assertion is intended to exercise so the test
	// does not depend on whether the runner uses umask 0002 or 0022.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	publishHubShare(t, hub, "code", dir, true)

	tagNode, errno := hubLookup(t, hub, 3, 1, "code")
	if errno != 0 || tagNode <= 1 {
		t.Fatalf("dynamic share lookup node=%d errno=%d", tagNode, errno)
	}
	getattrIn := make([]byte, 16)
	if _, errno, attrOut := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseGetattr, 30, tagNode, len(getattrIn)), getattrIn}, 16, 104); errno != 0 {
		t.Fatalf("export root getattr errno %d", errno)
	} else if mode := binary.LittleEndian.Uint32(attrOut[1][76:80]); mode&uint32(syscall.S_IFMT) != uint32(syscall.S_IFDIR) || mode&0o777 != 0o755 {
		t.Fatalf("export root mode %#o, want directory mode 0755", mode)
	}
	opendirIn := make([]byte, 8)
	_, errno, _ = hubReq(t, hub,
		[][]byte{fuseInHeader(fuseOpendir, 31, tagNode, len(opendirIn)), opendirIn}, 16, 16)
	if runtime.GOOS == "windows" && errno != 0 {
		t.Fatalf("Windows export root opendir errno %d", errno)
	} else if runtime.GOOS != "windows" && errno != -linuxENOSYS {
		t.Fatalf("export root opendir errno %d, want Linux ENOSYS", errno)
	}
	fileNode, errno := hubLookup(t, hub, 4, tagNode, "hello.txt")
	if errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}
	openIn := make([]byte, 8)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseOpen, 5, fileNode, len(openIn)), openIn}, 16, 16); errno != 0 {
		t.Fatalf("read-only open errno %d", errno)
	}
	binary.LittleEndian.PutUint32(openIn[0:4], 1) // O_WRONLY
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseOpen, 6, fileNode, len(openIn)), openIn}, 16, 16); errno != erofs {
		t.Fatalf("writable open on RO export errno %d, want EROFS", errno)
	}

	if _, err := hub.Remove("code", true); err != nil {
		t.Fatal(err)
	}
	if node, errno := hubLookup(t, hub, 7, 1, "code"); node != 0 || errno != 0 {
		t.Fatalf("removed share lookup node=%d errno=%d, want negative node 0", node, errno)
	}
	revokedIn := make([]byte, 16)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseGetattr, 8, fileNode, len(revokedIn)), revokedIn}, 16, 104); errno != estale {
		t.Fatalf("forced revoked node getattr errno %d, want ESTALE", errno)
	}
	listIn := make([]byte, 8)
	binary.LittleEndian.PutUint32(listIn[:4], 4096)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseListxattr, 9, fileNode, len(listIn)), listIn}, 16, 4096); errno != estale {
		t.Fatalf("forced revoked node listxattr errno %d, want ESTALE", errno)
	}
}

func TestShareHubPinsRenamedHostRoot(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	fuseInitHub(t, hub)

	parent := t.TempDir()
	original := filepath.Join(parent, "original")
	moved := filepath.Join(parent, "moved")
	if err := os.Mkdir(original, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(original, "pinned.txt"), []byte("old root\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	publishHubShare(t, hub, "code", original, true)
	tagNode, errno := hubLookup(t, hub, 2, 1, "code")
	if errno != 0 {
		t.Fatal(errno)
	}
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, errno := hubLookup(t, hub, 3, tagNode, "pinned.txt"); errno != 0 {
		t.Fatalf("pinned root lookup after rename errno %d", errno)
	}

	// The replacement directory at the original path must not retarget
	// opens: reads have to come from the pinned (renamed) root.
	if err := os.WriteFile(filepath.Join(original, "pinned.txt"), []byte("REPLACEMENT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fileNode, errno := hubLookup(t, hub, 4, tagNode, "pinned.txt")
	if errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}
	openIn := make([]byte, 8)
	_, errno, openOut := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseOpen, 5, fileNode, len(openIn)), openIn}, 16, 16)
	if errno != 0 {
		t.Fatalf("open errno %d", errno)
	}
	readIn := make([]byte, 40)
	copy(readIn[0:8], openOut[1][0:8])                 // fh
	binary.LittleEndian.PutUint32(readIn[16:20], 4096) // size
	_, errno, readOut := hubReq(t, hub,
		[][]byte{fuseInHeader(15 /* fuseRead */, 6, fileNode, len(readIn)), readIn}, 16, 4096)
	if errno != 0 {
		t.Fatalf("read errno %d", errno)
	}
	if got := string(readOut[1][:9]); got != "old root\n" {
		t.Fatalf("read %q, want content from the pinned (renamed) root", got)
	}
}

func TestShareHubReadSupportsFragmentedVirtqueuePayload(t *testing.T) {
	const content = "fragmented-response\n"
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	fuseInitHub(t, hub)
	publishHubShare(t, hub, "code", root, true)
	tagNode, errno := hubLookup(t, hub, 2, 1, "code")
	if errno != 0 {
		t.Fatalf("share lookup errno %d", errno)
	}
	fileNode, errno := hubLookup(t, hub, 3, tagNode, "hello.txt")
	if errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}

	openIn := make([]byte, 8)
	_, errno, openOut := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseOpen, 4, fileNode, len(openIn)), openIn}, 16, 16)
	if errno != 0 {
		t.Fatalf("open errno %d", errno)
	}

	const readSize = 128 << 10
	readIn := make([]byte, 40)
	copy(readIn[0:8], openOut[1][0:8])
	binary.LittleEndian.PutUint32(readIn[16:20], readSize)
	outSizes := []int{16, 16}
	for capacity := 16; capacity < readSize; capacity += 4096 {
		outSizes = append(outSizes, 4096)
	}
	n, errno, readOut := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseRead, 5, fileNode, len(readIn)), readIn}, outSizes...)
	if errno != 0 {
		t.Fatalf("fragmented read errno %d", errno)
	}
	if n != 16+len(content) {
		t.Fatalf("fragmented read length %d, want %d", n, 16+len(content))
	}
	payload := append(append([]byte(nil), readOut[1]...), readOut[2]...)
	if got := string(payload[:len(content)]); got != content {
		t.Fatalf("fragmented read = %q, want %q", got, content)
	}
}

func TestShareHubRetainedNodeMetadataCannotFollowSwappedParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows backend uses handle-relative traversal")
	}
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	fuseInitHub(t, hub)

	root := t.TempDir()
	inside := filepath.Join(root, "inside")
	moved := filepath.Join(root, "moved")
	outside := t.TempDir()
	if err := os.Mkdir(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(inside, "file"), filepath.Join(outside, "file")} {
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	export := publishHubShare(t, hub, "code", root, false)
	tagNode, errno := hubLookup(t, hub, 2, 1, "code")
	if errno != 0 {
		t.Fatalf("share lookup errno %d", errno)
	}
	insideNode, errno := hubLookup(t, hub, 3, tagNode, "inside")
	if errno != 0 {
		t.Fatalf("directory lookup errno %d", errno)
	}
	fileNode, errno := hubLookup(t, hub, 4, insideNode, "file")
	if errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}
	outsideExport := publishHubShare(t, hub, "outside", outside, false)
	outsideTag, errno := hubLookup(t, hub, 5, 1, outsideExport.Tag)
	if errno != 0 {
		t.Fatalf("outside share lookup errno %d", errno)
	}
	outsideFile, errno := hubLookup(t, hub, 6, outsideTag, "file")
	if errno != 0 {
		t.Fatalf("outside file lookup errno %d", errno)
	}
	setXattr := func(unique, node uint64, name, value string) int32 {
		in := make([]byte, 8)
		binary.LittleEndian.PutUint32(in[:4], uint32(len(value)))
		payload := append(in, append([]byte(name+"\x00"), []byte(value)...)...)
		_, errno, _ := hubReq(t, hub,
			[][]byte{fuseInHeader(fuseSetxattr, unique, node, len(payload)), payload}, 16)
		return errno
	}
	if errno := setXattr(7, outsideFile, "user.outside", "outside"); errno != 0 {
		t.Fatalf("seed outside xattr errno %d", errno)
	}

	// Keep the FUSE inode alive while its original parent name is replaced
	// with a symlink to an outside directory. Metadata operations on the
	// retained node must walk from the pinned root and reject that symlink.
	if err := os.Rename(inside, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, inside); err != nil {
		t.Fatal(err)
	}

	listIn := make([]byte, 8)
	binary.LittleEndian.PutUint32(listIn[:4], 4096)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseListxattr, 8, fileNode, len(listIn)), listIn}, 16, 4096); errno == 0 {
		t.Fatal("listxattr followed a swapped intermediate symlink outside the export")
	}
	getIn := make([]byte, 8)
	binary.LittleEndian.PutUint32(getIn[:4], 4096)
	getPayload := append(getIn, []byte("user.outside\x00")...)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseGetxattr, 9, fileNode, len(getPayload)), getPayload}, 16, 4096); errno == 0 {
		t.Fatal("getxattr followed a swapped intermediate symlink outside the export")
	}
	if errno := setXattr(10, fileNode, "user.escape", "changed"); errno == 0 {
		t.Fatal("setxattr followed a swapped intermediate symlink outside the export")
	}
	removePayload := []byte("user.outside\x00")
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseRemovexattr, 11, fileNode, len(removePayload)), removePayload}, 16); errno == 0 {
		t.Fatal("removexattr followed a swapped intermediate symlink outside the export")
	}

	statxIn := make([]byte, 24)
	binary.LittleEndian.PutUint32(statxIn[20:24], 0x07ff)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseStatx, 12, fileNode, len(statxIn)), statxIn}, 16, 288); errno == 0 {
		t.Fatal("statx followed a swapped intermediate symlink outside the export")
	}

	if _, err := hub.Remove(export.Tag, true); err != nil {
		t.Fatal(err)
	}
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseListxattr, 13, fileNode, len(listIn)), listIn}, 16, 4096); errno != -int32(fuse.ESTALE) {
		t.Fatalf("revoked node listxattr errno %d, want ESTALE", errno)
	}
}

func TestShareHubRenameWithinExport(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	fuseInitHub(t, hub)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "before.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	publishHubShare(t, hub, "code", dir, false)
	tagNode, errno := hubLookup(t, hub, 2, 1, "code")
	if errno != 0 {
		t.Fatal(errno)
	}
	oldName := append([]byte("before.txt"), 0)
	newName := append([]byte("after.txt"), 0)
	renameIn := make([]byte, 8)
	binary.LittleEndian.PutUint64(renameIn, tagNode)
	payload := append(renameIn, oldName...)
	payload = append(payload, newName...)
	_, errno, _ = hubReq(t, hub,
		[][]byte{fuseInHeader(12, 3, tagNode, len(payload)), payload}, 16)
	if errno != 0 {
		t.Fatalf("rename errno %d", errno)
	}
	fileNode, errno := hubLookup(t, hub, 4, tagNode, "after.txt")
	if errno != 0 {
		t.Fatalf("renamed lookup errno %d", errno)
	}
	getattrIn := make([]byte, 16)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseGetattr, 5, fileNode, len(getattrIn)), getattrIn}, 16, 104); errno != 0 {
		t.Fatalf("renamed node getattr errno %d", errno)
	}
}

func TestShareHubCrossExportRenameRejected(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	fuseInitHub(t, hub)

	left, right := t.TempDir(), t.TempDir()
	for _, dir := range []string{left, right} {
		if err := os.WriteFile(filepath.Join(dir, "file"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	publishHubShare(t, hub, "left", left, false)
	publishHubShare(t, hub, "right", right, false)
	leftNode, errno := hubLookup(t, hub, 2, 1, "left")
	if errno != 0 {
		t.Fatal(errno)
	}
	rightNode, errno := hubLookup(t, hub, 3, 1, "right")
	if errno != 0 {
		t.Fatal(errno)
	}
	// RENAME payload: two NUL-terminated names. The header nodeid is the old
	// parent; the payload begins with the new parent nodeid.
	name := append([]byte("file"), 0)
	renameIn := make([]byte, 8)
	binary.LittleEndian.PutUint64(renameIn, rightNode)
	payload := append(renameIn, name...)
	payload = append(payload, name...)
	_, errno, _ = hubReq(t, hub,
		[][]byte{fuseInHeader(12, 4, leftNode, len(payload)), payload}, 16)
	if errno != -18 { // Linux EXDEV
		t.Fatalf("cross-export rename errno %d, want EXDEV", errno)
	}
	if _, err := os.Stat(filepath.Join(left, "file")); err != nil {
		t.Fatal("rename escaped the left export")
	}
}

// TestShareHubDefaultDenyOps covers the hub's default-deny operation
// policy over the FUSE wire: host-side ioctls, special-file creation and
// non-user xattrs all execute with the VMM's credentials and must never
// cross the guest boundary, even inside a writable export.
func TestShareHubDefaultDenyOps(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	fuseInitHub(t, hub)

	const (
		fuseMknod = 8
		fuseIoctl = 39
		eperm     = -1
		enosys    = -38
		enotsup   = -95
	)

	// Wire errnos are Linux numbers on every platform. The Unix backend
	// denies with EPERM by policy; the Windows passthrough backend has no
	// special-file or xattr concept at all, so its deny arrives as ENOSYS.
	denyMknod, denyXattr, allowUser := int32(eperm), int32(eperm), int32(0)
	if runtime.GOOS == "windows" {
		denyMknod, denyXattr, allowUser = enosys, enosys, enosys
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	publishHubShare(t, hub, "work", dir, false)

	tagNode, errno := hubLookup(t, hub, 2, 1, "work")
	if errno != 0 {
		t.Fatalf("share lookup errno %d", errno)
	}

	// MKNOD: a guest must not plant special files on the host.
	mknodIn := make([]byte, 16)
	binary.LittleEndian.PutUint32(mknodIn[0:4], uint32(syscall.S_IFCHR|0o644))
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseMknod, 3, tagNode, len(mknodIn)+5), mknodIn, []byte("dev0\x00")}, 16, 128); errno != denyMknod {
		t.Errorf("mknod errno %d, want EPERM (ENOSYS on Windows)", errno)
	}

	fileNode, errno := hubLookup(t, hub, 4, tagNode, "file.txt")
	if errno != 0 {
		t.Fatalf("file lookup errno %d", errno)
	}

	// XATTR writes: only user.* may cross the boundary.
	setxattr := func(unique uint64, name, value string) int32 {
		in := make([]byte, 8) // fuse SetXAttrIn: size, flags
		binary.LittleEndian.PutUint32(in[0:4], uint32(len(value)))
		payload := append(in, append([]byte(name+"\x00"), []byte(value)...)...)
		_, errno, _ := hubReq(t, hub,
			[][]byte{fuseInHeader(fuseSetxattr, unique, fileNode, len(payload)), payload}, 16, 16)
		return errno
	}
	for i, attr := range []string{"security.capability", "trusted.overlay.opaque", "system.posix_acl_access"} {
		if errno := setxattr(uint64(10+i), attr, "x"); errno != denyXattr {
			t.Errorf("setxattr %s errno %d, want EPERM (ENOSYS on Windows)", attr, errno)
		}
		removeIn := []byte(attr + "\x00")
		if _, errno, _ := hubReq(t, hub,
			[][]byte{fuseInHeader(fuseRemovexattr, 20, fileNode, len(removeIn)), removeIn}, 16, 16); errno != denyXattr {
			t.Errorf("removexattr %s errno %d, want EPERM (ENOSYS on Windows)", attr, errno)
		}
	}
	if errno := setxattr(30, "user.gantry", "x"); errno != allowUser {
		t.Errorf("setxattr user.* errno %d, want allowed (ENOSYS on Windows)", errno)
	}

	// IOCTL: default-deny even though the host permits mutating ioctls
	// (FS_IOC_SETFLAGS et al.) through O_RDONLY descriptors.
	openIn := make([]byte, 8)
	_, errno, openOut := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseOpen, 40, fileNode, len(openIn)), openIn}, 16, 16)
	if errno != 0 {
		t.Fatalf("open errno %d", errno)
	}
	ioctlIn := make([]byte, 32)         // fh, flags, cmd, arg, inSize, outSize
	copy(ioctlIn[0:8], openOut[1][0:8]) // fh
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseIoctl, 41, fileNode, len(ioctlIn)), ioctlIn}, 16, 16); errno != enotsup {
		t.Errorf("ioctl errno %d, want ENOTSUP", errno)
	}
}

// TestShareHubSwapRevokesReplacedExport: Swap installs the replacement
// atomically — the tag never disappears from the namespace — and revokes
// the old export, so its nodes and open handles fail ESTALE.
func TestShareHubSwapRevokesReplacedExport(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	fuseInitHub(t, hub)

	const estale = -116
	oldDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(oldDir, "a.txt"), []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	publishHubShare(t, hub, "code", oldDir, true)
	tagNode, errno := hubLookup(t, hub, 2, 1, "code")
	if errno != 0 {
		t.Fatalf("share lookup errno %d", errno)
	}
	oldFile, errno := hubLookup(t, hub, 3, tagNode, "a.txt")
	if errno != 0 {
		t.Fatalf("old file lookup errno %d", errno)
	}
	openIn := make([]byte, 8)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseOpen, 4, oldFile, len(openIn)), openIn}, 16, 16); errno != 0 {
		t.Fatalf("open before swap errno %d", errno)
	}

	newDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(newDir, "b.txt"), []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prepared, _, err := hub.Prepare("code", newDir, true)
	if err != nil {
		t.Fatal(err)
	}
	oldExport, newExport, err := hub.Swap(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if oldExport.State() != ExportRevoked {
		t.Errorf("old export state %v, want revoked", oldExport.State())
	}
	if newExport.State() != ExportActive {
		t.Errorf("new export state %v, want active", newExport.State())
	}

	// The tag resolves to the replacement immediately.
	newTag, errno := hubLookup(t, hub, 5, 1, "code")
	if errno != 0 {
		t.Fatalf("tag lookup after swap errno %d", errno)
	}
	if _, errno := hubLookup(t, hub, 6, newTag, "b.txt"); errno != 0 {
		t.Fatalf("replacement file lookup errno %d", errno)
	}
	if node, _ := hubLookup(t, hub, 7, newTag, "a.txt"); node != 0 {
		t.Fatal("old file still visible after swap")
	}

	// The old export's nodes and open handles are revoked.
	getattrIn := make([]byte, 16)
	if _, errno, _ := hubReq(t, hub,
		[][]byte{fuseInHeader(fuseGetattr, 8, oldFile, len(getattrIn)), getattrIn}, 16, 104); errno != estale {
		t.Errorf("old node getattr errno %d, want ESTALE", errno)
	}

	// Publish of the live tag still conflicts.
	p2, _, err := hub.Prepare("code", oldDir, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hub.Publish(p2); err == nil {
		t.Error("Publish on a swapped-in tag succeeded, want conflict")
		p2.Close()
	} else {
		p2.Close()
	}
}

func TestExportStateCannotRegressAfterFinish(t *testing.T) {
	export := &Export{}
	export.state.Store(int32(ExportActive))
	export.finish()

	// Hub.Close can race an inode's OnForget. A late revoke must not move a
	// fully released export back out of the terminal Gone state.
	export.advanceState(ExportRevoked)
	if got := export.State(); got != ExportGone {
		t.Fatalf("state after finish then revoke = %s, want gone", got)
	}
}

func TestShareHubOwnerMappingRejectedWhereUnsupported(t *testing.T) {
	if shareOwnerMappingSupported {
		t.Skip("ownership mapping is supported on this platform")
	}
	// PrepareMapped must fail loudly rather than silently report the
	// host's real ownership on platforms whose backend cannot map.
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	uid, gid := uint32(1000), uint32(1000)
	if _, _, err := hub.PrepareMapped("workspace", t.TempDir(), false, &uid, &gid); err == nil {
		t.Fatal("want an explicit unsupported-platform error")
	}
}

func TestShareHubRootMtimeTracksNamespace(t *testing.T) {
	// The guest kernel invalidates its cached READDIR of the mount
	// root only on mtime change; a static mtime made hot-added tags
	// invisible until remount on legacy guests. The root remains uncached even
	// when Gantry's reverse-notification queue is negotiated.
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()

	before := hub.rootVer.Load()
	time.Sleep(2 * time.Millisecond)
	publishHubShare(t, hub, "fresh", t.TempDir(), true)
	after := hub.rootVer.Load()
	if after <= before {
		t.Fatalf("namespace version did not advance on publish: before=%d after=%d", before, after)
	}
	var out fuse.AttrOut
	if errno := hub.root.Getattr(context.Background(), nil, &out); errno != 0 {
		t.Fatalf("root getattr errno %d", errno)
	}
	if out.Mtime != uint64(after/int64(time.Second)) || out.Mtimensec != uint32(after%int64(time.Second)) {
		t.Fatalf("root getattr reports mtime %d.%09d, want %d", out.Mtime, out.Mtimensec, after)
	}
	// Removal advances it too.
	before = after
	time.Sleep(2 * time.Millisecond)
	if _, err := hub.Remove("fresh", false); err != nil {
		t.Fatal(err)
	}
	if hub.rootVer.Load() <= before {
		t.Fatal("namespace version did not advance on remove")
	}
}

func TestShareHubForgetsFinishedExports(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()

	publishHubShare(t, hub, "code", t.TempDir(), true)
	for range 32 {
		prepared, _, err := hub.Prepare("code", t.TempDir(), true)
		if err != nil {
			t.Fatal(err)
		}
		old, _, err := hub.Swap(prepared)
		if err != nil {
			prepared.Close()
			t.Fatal(err)
		}
		// Model the kernel's final FORGET after the replacement. The export
		// must release both its root and the hub's ownership reference.
		old.finish()
	}

	hub.mu.RLock()
	retained := len(hub.all)
	hub.mu.RUnlock()
	if retained != 1 {
		t.Fatalf("hub retained %d exports after replacements, want one active export", retained)
	}

	removed, err := hub.Remove("code", true)
	if err != nil {
		t.Fatal(err)
	}
	removed.finish()
	hub.mu.RLock()
	retained = len(hub.all)
	hub.mu.RUnlock()
	if retained != 0 {
		t.Fatalf("hub retained %d exports after final removal", retained)
	}
}

func TestPreparedIdentityPinsSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows share roots deliberately reject reparse points")
	}
	oldRoot := t.TempDir()
	newRoot := t.TempDir()
	link := filepath.Join(t.TempDir(), "share")
	if err := os.Symlink(oldRoot, link); err != nil {
		t.Fatal(err)
	}

	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	prepared, canonical, err := hub.Prepare("code", link, true)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()

	// Swap the caller-controlled name after preparation. Publication must
	// retain the object opened above, not follow the new symlink target.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(newRoot, link); err != nil {
		t.Fatal(err)
	}
	oldIdentity, err := Identify(oldRoot)
	if err != nil {
		t.Fatal(err)
	}
	newIdentity, err := Identify(newRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.Identity().Aliases(oldIdentity) || prepared.Identity().Aliases(newIdentity) {
		t.Fatalf("prepared identity did not retain opened root: path=%q old=%q new=%q", canonical, oldIdentity.Path(), newIdentity.Path())
	}
	if canonical != oldIdentity.Path() {
		t.Fatalf("canonical path came from caller name, got %q want pinned path %q", canonical, oldIdentity.Path())
	}
	export, err := hub.Publish(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if !export.Identity().Aliases(oldIdentity) || export.Path != canonical {
		t.Fatalf("published export changed identity: path=%q identity=%q", export.Path, export.Identity().Path())
	}
}

func TestIdentityOverlapUsesObjectAndPath(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	sibling := t.TempDir()
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	rootIdentity, err := Identify(root)
	if err != nil {
		t.Fatal(err)
	}
	aliasIdentity, err := Identify(root)
	if err != nil {
		t.Fatal(err)
	}
	childIdentity, err := Identify(child)
	if err != nil {
		t.Fatal(err)
	}
	siblingIdentity, err := Identify(sibling)
	if err != nil {
		t.Fatal(err)
	}
	if !rootIdentity.Aliases(aliasIdentity) {
		t.Fatal("same directory was not recognized as an object alias")
	}
	if !rootIdentity.Overlaps(childIdentity) {
		t.Fatal("ancestor and child identities did not overlap")
	}
	if rootIdentity.Overlaps(siblingIdentity) {
		t.Fatal("unrelated sibling identities overlapped")
	}
}

type blockingFuseHandler struct {
	entered chan struct{}
	unblock chan struct{}
	once    sync.Once
}

func newBlockingFuseHandler() *blockingFuseHandler {
	return &blockingFuseHandler{
		entered: make(chan struct{}),
		unblock: make(chan struct{}),
	}
}

func (h *blockingFuseHandler) HandleRequest(_, _ [][]byte) (int, fuse.Status) {
	h.once.Do(func() { close(h.entered) })
	<-h.unblock
	return 0, fuse.OK
}

// waitForQueuedWriter waits until a writer is queued behind the deliberately
// held read lock. RWMutex gives queued writers priority over new readers, so a
// failed TryRLock is a deterministic indication that Close reached Lock.
func waitForQueuedWriter(t *testing.T, lock *sync.RWMutex) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for lock.TryRLock() {
		lock.RUnlock()
		if time.Now().After(deadline) {
			t.Fatal("Close did not wait on the in-flight request")
		}
		runtime.Gosched()
	}
}

func assertCloseDrainsRequest(
	t *testing.T,
	lock *sync.RWMutex,
	handler *blockingFuseHandler,
	handle func(),
	closeResource func() error,
	released <-chan struct{},
) {
	t.Helper()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		handle()
	}()
	<-handler.entered

	closeDone := make(chan error, 1)
	go func() { closeDone <- closeResource() }()
	waitForQueuedWriter(t, lock)
	select {
	case <-released:
		t.Fatal("Close released the pinned root while a request was active")
	default:
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned while a request was active: %v", err)
	default:
	}

	close(handler.unblock)
	<-requestDone
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-released:
	default:
		t.Fatal("Close did not release the pinned root after draining requests")
	}
}

func TestShareHubCloseDrainsRequestsBeforeRelease(t *testing.T) {
	handler := newBlockingFuseHandler()
	released := make(chan struct{})
	export := &Export{release: func() { close(released) }}
	export.state.Store(int32(ExportActive))
	hub := &Hub{
		handler: handler,
		exports: map[string]*Export{"code": export},
		all:     map[*Export]struct{}{export: {}},
	}

	assertCloseDrainsRequest(t, &hub.request, handler,
		func() { _, _ = hub.HandleRequest(nil, nil) }, hub.Close, released)
	if got := export.State(); got != ExportGone {
		t.Fatalf("export state after Close = %s, want gone", got)
	}
}

func TestShareServerCloseDrainsRequestsBeforeRelease(t *testing.T) {
	handler := newBlockingFuseHandler()
	released := make(chan struct{})
	export := &Export{release: func() { close(released) }}
	export.state.Store(int32(ExportActive))
	server := &Server{handler: handler, export: export}

	assertCloseDrainsRequest(t, &server.request, handler,
		func() { _, _ = server.HandleRequest(nil, nil) }, server.Close, released)
	if got := export.State(); got != ExportGone {
		t.Fatalf("export state after Close = %s, want gone", got)
	}
}

func BenchmarkShareHubRootGetattr(b *testing.B) {
	hub, err := NewHub()
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = hub.Close() })
	for i := 0; i < 32; i++ {
		publishHubShare(b, hub, fmt.Sprintf("share-%d", i), b.TempDir(), true)
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		var out fuse.AttrOut
		if errno := hub.root.Getattr(ctx, nil, &out); errno != 0 {
			b.Fatalf("root getattr errno %d", errno)
		}
	}
}
