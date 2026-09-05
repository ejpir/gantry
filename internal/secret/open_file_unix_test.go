//go:build !windows

package secret

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFileSourceRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(canonicalTempDir(t), "secret.fifo")
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

func TestFileSourceRejectsSymlinksAndHardLinks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("host-secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	finalLink := filepath.Join(root, "final-link")
	if err := os.Symlink(target, finalLink); err != nil {
		t.Fatal(err)
	}
	assertFileSourceRejected(t, finalLink, "symlink-free")
	if _, err := ParseFile(finalLink); err == nil || !strings.Contains(err.Error(), "symlink-free") {
		t.Fatalf("dotenv symlink error = %v", err)
	}
	if _, err := ParseSpec("TOKEN=@"+finalLink, func(string) (string, bool) { return "", false }); err == nil || !strings.Contains(err.Error(), "symlink-free") {
		t.Fatalf("eager file-secret symlink error = %v", err)
	}

	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(realDir, "token")
	if err := os.WriteFile(inside, []byte("host-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(root, "dir-link")
	if err := os.Symlink(realDir, dirLink); err != nil {
		t.Fatal(err)
	}
	assertFileSourceRejected(t, filepath.Join(dirLink, "token"), "symlink-free")

	hardLink := filepath.Join(root, "hard-link")
	if err := os.Link(target, hardLink); err != nil {
		t.Fatal(err)
	}
	assertFileSourceRejected(t, hardLink, "multiple hard links")
}

func TestFileSourceAcceptsCanonicalSingleLinkFile(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "token")
	if err := os.WriteFile(path, []byte("value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(nil, nil)
	store.Put("TOKEN", Source{Kind: SourceFile, Ref: path})
	value, err := store.Resolve("TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if value.Raw() != "value" {
		t.Fatalf("resolved value = %q", value.Raw())
	}
}

func TestDarwinFileSourceRejectsVarAlias(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin filesystem alias regression")
	}
	rawDir := t.TempDir()
	canonical, err := filepath.EvalSymlinks(rawDir)
	if err != nil {
		t.Fatal(err)
	}
	if canonical == rawDir {
		t.Skip("temporary directory already uses a canonical path")
	}
	path := filepath.Join(rawDir, "token")
	if err := os.WriteFile(path, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertFileSourceRejected(t, path, "symlink-free")
}

func assertFileSourceRejected(t *testing.T, path, want string) {
	t.Helper()
	store := NewStore(nil, nil)
	store.Put("TOKEN", Source{Kind: SourceFile, Ref: path})
	if _, err := store.Resolve("TOKEN"); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("source %q error = %v, want %q", path, err, want)
	}
}
