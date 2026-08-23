//go:build windows

package sharefs

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestValidWinGuestName(t *testing.T) {
	valid := []string{"hello.txt", "README", "a b", "café", ".hidden"}
	for _, name := range valid {
		if !validWinGuestName(name) {
			t.Errorf("validWinGuestName(%q) = false", name)
		}
	}
	invalid := []string{"", ".", "..", `a\b`, "a/b", "a:b", "NUL", "con.txt", "COM1", "LPT9", "trail.", "trail "}
	for _, name := range invalid {
		if validWinGuestName(name) {
			t.Errorf("validWinGuestName(%q) = true", name)
		}
	}
}

func TestWinGuestInoAvoidsReservedValues(t *testing.T) {
	for _, fileID := range []uint64{0, fuse.FUSE_ROOT_ID} {
		if ino := winGuestIno(0, fileID, 0); ino == 0 || ino == fuse.FUSE_ROOT_ID {
			t.Fatalf("winGuestIno(0, %d, 0) returned reserved inode %d", fileID, ino)
		}
	}
}

func TestWinNodeRejectsSiblingFileHandle(t *testing.T) {
	export := &Export{}
	backend := &winExportFS{}
	owner := &winShareNode{export: export, backend: backend}
	sibling := &winShareNode{export: export, backend: backend}
	foreign := &winShareFile{
		wf:      &winOpenFile{},
		backend: backend,
		export:  export,
		node:    owner,
	}

	if errno := sibling.Setattr(context.Background(), foreign, &fuse.SetAttrIn{}, &fuse.AttrOut{}); errno != syscall.EBADF {
		t.Fatalf("Setattr sibling handle = %v, want EBADF", errno)
	}
	if errno := sibling.Getattr(context.Background(), foreign, &fuse.AttrOut{}); errno != syscall.EBADF {
		t.Fatalf("Getattr sibling handle = %v, want EBADF", errno)
	}
}

func TestWinExportRootGetattrAcceptsDirectoryHandle(t *testing.T) {
	root := t.TempDir()
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	prepared, _, err := hub.Prepare("root", root, false)
	if err != nil {
		t.Fatal(err)
	}
	export, err := hub.Publish(prepared)
	if err != nil {
		t.Fatal(err)
	}
	node, ok := export.node.(*winShareNode)
	if !ok {
		t.Fatalf("export node = %T, want *winShareNode", export.node)
	}
	stream, errno := node.Readdir(context.Background())
	if errno != 0 {
		t.Fatalf("readdir: %v", fuse.ToStatus(errno))
	}
	defer stream.Close()

	var out fuse.AttrOut
	if errno := node.Getattr(context.Background(), stream, &out); errno != 0 {
		t.Fatalf("getattr with directory handle: %v", fuse.ToStatus(errno))
	}
	if out.Mode&fuse.S_IFMT != fuse.S_IFDIR {
		t.Fatalf("getattr mode = %#o, want directory", out.Mode)
	}
}

func TestWinDirEntryDecoderRejectsOverlappingRecord(t *testing.T) {
	export := &Export{}
	stream := &winShareDirStream{
		buffer: new([winDirBufferSize]byte),
		export: export,
		dots:   2,
		valid:  256,
	}
	record := stream.buffer[:stream.valid]
	binary.LittleEndian.PutUint32(record, winDirEntryName) // too short for the name below
	binary.LittleEndian.PutUint32(record[winDirEntryNameLen:], 4)
	if _, errno := stream.readEntryLocked(); fuse.ToStatus(errno) != fuse.EIO {
		t.Fatalf("readEntryLocked status = %v, want EIO", fuse.ToStatus(errno))
	}
}

func TestWinDirEntryDecoder(t *testing.T) {
	export := &Export{}
	stream := &winShareDirStream{
		buffer: new([winDirBufferSize]byte),
		export: export,
		volume: 7,
		salt:   11,
		dots:   2,
		valid:  256,
	}
	record := stream.buffer[:stream.valid]
	name := utf16.Encode([]rune("folder"))
	binary.LittleEndian.PutUint32(record[winDirEntryAttrs:], uint32(syscall.FILE_ATTRIBUTE_DIRECTORY))
	binary.LittleEndian.PutUint32(record[winDirEntryNameLen:], uint32(len(name)*2))
	binary.LittleEndian.PutUint64(record[winDirEntryFileID:], 13)
	for i, unit := range name {
		binary.LittleEndian.PutUint16(record[winDirEntryName+i*2:], unit)
	}
	entry, errno := stream.readEntryLocked()
	if errno != 0 {
		t.Fatalf("readEntryLocked: %v", fuse.ToStatus(errno))
	}
	if entry.Name != "folder" || entry.Mode != fuse.S_IFDIR || entry.Ino != winGuestIno(7, 13, 11) {
		t.Fatalf("decoded entry = %+v", *entry)
	}
}

func TestWinAppendIsAtomicAcrossHandles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "append.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	backend, err := newWinExportFS(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	first, _, errno := backend.open("append.log", 2|linuxOAppend)
	if errno != 0 {
		t.Fatalf("open first: %v", fuse.ToStatus(errno))
	}
	defer func() { _ = first.close() }()
	second, _, errno := backend.open("append.log", 2|linuxOAppend)
	if errno != 0 {
		t.Fatalf("open second: %v", fuse.ToStatus(errno))
	}
	defer func() { _ = second.close() }()

	const writes = 200
	lines := [2][]byte{[]byte("AAAAAAAA\n"), []byte("BBBBBBBB\n")}
	files := [2]*winOpenFile{first, second}
	var wg sync.WaitGroup
	for i := range files {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			for range writes {
				if n, err := files[index].write(lines[index], 0); err != nil || n != len(lines[index]) {
					t.Errorf("append %d: n=%d err=%v", index, n, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := writes * (len(lines[0]) + len(lines[1])); len(data) != want {
		t.Fatalf("append size = %d, want %d", len(data), want)
	}
	for _, line := range lines {
		if got := bytes.Count(data, line); got != writes {
			t.Fatalf("count %q = %d, want %d", line, got, writes)
		}
	}
}

func TestWinExportFSNativePassthrough(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	backend, err := newWinExportFS(root, 123<<32)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	identity, err := Identify(root)
	if err != nil {
		t.Fatal(err)
	}
	if !backend.identity.Aliases(identity) {
		t.Fatalf("handle-derived root identity mismatch: backend=%q resolved=%q", backend.identity.Path(), identity.Path())
	}

	info, errno := backend.lookup("", "hello.txt")
	if errno != 0 {
		t.Fatalf("lookup errno %d", fuse.ToStatus(errno))
	}
	if info.attr.Mode&fuse.S_IFREG == 0 || info.attr.Size != 5 {
		t.Fatalf("hello attr %+v", info.attr)
	}
	if _, errno := backend.lookup("", "HELLO.TXT"); errno == 0 {
		t.Fatal("case-variant lookup succeeded; want exact-case ENOENT")
	}

	file, _, errno := backend.open("hello.txt", 0)
	if errno != 0 {
		t.Fatalf("open errno %d", fuse.ToStatus(errno))
	}
	buf := make([]byte, 5)
	if n, err := file.read(buf, 0); err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("read n=%d err=%v", n, err)
	}
	if err := file.close(); err != nil {
		t.Fatal(err)
	}

	created, info, errno := backend.create("", "new.txt", 2|linuxOCreat|linuxOTrunc, 0o644)
	if errno != 0 {
		t.Fatalf("create errno %d", fuse.ToStatus(errno))
	}
	if _, err := created.write([]byte("new"), 0); err != nil {
		t.Fatal(err)
	}
	if err := created.close(); err != nil {
		t.Fatal(err)
	}
	if info.attr.Mode&fuse.S_IFREG == 0 {
		t.Fatalf("created mode %#o", info.attr.Mode)
	}

	if _, errno := backend.mkdir("", "subdir"); errno != 0 {
		t.Fatalf("mkdir errno %d", fuse.ToStatus(errno))
	}
	if errno := backend.rename("", "new.txt", "subdir", "renamed.txt", 0); errno != 0 {
		t.Fatalf("rename errno %d", fuse.ToStatus(errno))
	}
	if _, err := os.Stat(filepath.Join(root, "subdir", "renamed.txt")); err != nil {
		t.Fatal(err)
	}
	stream, errno := backend.readdir("", &Export{})
	if errno != 0 {
		t.Fatalf("readdir errno %d", fuse.ToStatus(errno))
	}
	stream.export.state.Store(int32(ExportActive))
	defer stream.Close()
	seen := map[string]bool{}
	for stream.HasNext() {
		entry, errno := stream.Next()
		if errno != 0 {
			t.Fatalf("readdir entry errno %d", fuse.ToStatus(errno))
		}
		seen[entry.Name] = true
	}
	if !seen["hello.txt"] || !seen["subdir"] {
		t.Fatalf("readdir missing entries: %+v", seen)
	}
	if errno := backend.delete("subdir", "renamed.txt", false); errno != 0 {
		t.Fatalf("delete errno %d", fuse.ToStatus(errno))
	}
	if errno := backend.delete("", "subdir", true); errno != 0 {
		t.Fatalf("rmdir errno %d", fuse.ToStatus(errno))
	}
}

func TestWinExportFSCreateWhileWatcherIsActive(t *testing.T) {
	root := t.TempDir()
	backend, err := newWinExportFS(root, 124<<32)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()

	export := &Export{watchRootHandle: uintptr(backend.root)}
	watcher, err := newPlatformShareWatcher(export, func(shareWatchEvent) {})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		closed := make(chan error, 1)
		go func() { closed <- watcher.Close() }()
		select {
		case err := <-closed:
			if err != nil {
				t.Errorf("close active watcher: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("closing active watcher did not cancel ReadDirectoryChangesW")
		}
	}()

	created, _, errno := backend.create("", "new.txt", 0x8241, 0o644)
	if errno != 0 {
		t.Fatalf("create with active watcher errno %d", fuse.ToStatus(errno))
	}
	if n, err := created.write([]byte("new"), 0); err != nil || n != 3 {
		t.Fatalf("write with active watcher n=%d err=%v", n, err)
	}
	if err := created.close(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "new.txt")); err != nil || string(got) != "new" {
		t.Fatalf("host content %q err=%v", got, err)
	}
}

func TestWinDirStreamReplaysForwardCookie(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	backend, err := newWinExportFS(root, 125<<32)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	export := &Export{}
	export.state.Store(int32(ExportActive))

	first, errno := backend.readdir("", export)
	if errno != 0 {
		t.Fatalf("first readdir errno %d", fuse.ToStatus(errno))
	}
	for range 4 {
		if _, errno := first.Next(); errno != 0 {
			first.Close()
			t.Fatalf("first stream errno %d", fuse.ToStatus(errno))
		}
	}
	first.Close()

	continued, errno := backend.readdir("", export)
	if errno != 0 {
		t.Fatalf("continued readdir errno %d", fuse.ToStatus(errno))
	}
	defer continued.Close()
	if errno := continued.Seekdir(context.Background(), 4); errno != 0 {
		t.Fatalf("seek continuation cookie errno %d", fuse.ToStatus(errno))
	}
	if continued.HasNext() {
		t.Fatal("continuation after all four entries unexpectedly has data")
	}
}

func TestWinExportFSRootRenameKeepsHandlePinned(t *testing.T) {
	parent := t.TempDir()
	original := filepath.Join(parent, "original")
	moved := filepath.Join(parent, "moved")
	if err := os.Mkdir(original, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(original, "pinned.txt"), []byte("pin"), 0o644); err != nil {
		t.Fatal(err)
	}
	backend, err := newWinExportFS(original, 456<<32)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, errno := backend.lookup("", "pinned.txt"); errno != 0 {
		t.Fatalf("lookup through renamed root errno %d", fuse.ToStatus(errno))
	}
}
