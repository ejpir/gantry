//go:build windows

package virtio

import (
	"os"
	"path/filepath"
	"testing"

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

func TestWinExportFSNativePassthrough(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	backend, err := newWinExportFS(root, 123<<32)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

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
	entries, errno := backend.readdir("")
	if errno != 0 {
		t.Fatalf("readdir errno %d", fuse.ToStatus(errno))
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		seen[entry.Name] = true
	}
	if !seen["hello.txt"] || !seen["subdir"] {
		t.Fatalf("readdir missing entries: %+v", entries)
	}
	if errno := backend.delete("subdir", "renamed.txt", false); errno != 0 {
		t.Fatalf("delete errno %d", fuse.ToStatus(errno))
	}
	if errno := backend.delete("", "subdir", true); errno != 0 {
		t.Fatalf("rmdir errno %d", fuse.ToStatus(errno))
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
	defer backend.Close()
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
