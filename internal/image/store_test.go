package image

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestStoreTempDirIsPrivateAndLocal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "images")
	store := NewStore(root)
	tmp, err := store.newTempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if got, want := filepath.Dir(tmp), filepath.Join(root, "tmp"); got != want {
		t.Fatalf("staging parent = %q, want %q", got, want)
	}
	if info, err := os.Stat(filepath.Join(root, "tmp")); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		// Windows reports synthesized Unix mode bits; the user-profile DACL is
		// the authority there.
		t.Fatalf("staging directory mode = %o, want private", info.Mode().Perm())
	}
}

func TestRemovePersistsIndexBeforeDeletingContent(t *testing.T) {
	s := NewStore(t.TempDir())
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("d", 64)
	ref := "registry.example/app:latest"
	for _, path := range []string{s.ErofsPath(digest), s.metaPath(digest), s.lockPath(digest)} {
		if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.writeIndex(map[string]string{refKey(ref, "arm64"): digest}); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("index write failed")
	s.writeIndexHook = func(map[string]string) error { return wantErr }
	if err := s.Remove(ref); !errors.Is(err, wantErr) {
		t.Fatalf("Remove error = %v, want %v", err, wantErr)
	}
	for _, path := range []string{s.ErofsPath(digest), s.metaPath(digest), s.lockPath(digest)} {
		if !fileExists(path) {
			t.Fatalf("%s was deleted before the index committed", path)
		}
	}
	if got, ok := s.LookupRef(ref, "arm64"); !ok || got != digest {
		t.Fatalf("index after failed removal = %q, %t", got, ok)
	}

	s.writeIndexHook = nil
	if err := s.Remove(ref); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.LookupRef(ref, "arm64"); ok {
		t.Fatal("successful removal retained the index entry")
	}
	for _, path := range []string{s.ErofsPath(digest), s.metaPath(digest), s.lockPath(digest)} {
		if fileExists(path) {
			t.Fatalf("successful removal retained %s", path)
		}
	}
}

// Concurrent builds of DIFFERENT digests must not lose each other's
// index entries or delete each other's temp files.
func TestStoreConcurrentEnsure(t *testing.T) {
	s := NewStore(t.TempDir())
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			digest := fmt.Sprintf("sha256:%064d", i)
			_, err := s.ensure(digest, func(outPath string) (*Meta, error) {
				if err := os.WriteFile(outPath, []byte(fmt.Sprintf("image-%d", i)), 0o600); err != nil {
					return nil, err
				}
				return &Meta{Ref: fmt.Sprintf("registry.test/img-%d:latest", i), Digest: digest, Arch: "arm64"}, nil
			})
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("ensure %d: %v", i, err)
		}
	}
	idx := s.readIndex()
	if len(idx) != n {
		t.Fatalf("index has %d entries after %d concurrent builds — entries lost", len(idx), n)
	}
	for i := 0; i < n; i++ {
		digest := fmt.Sprintf("sha256:%064d", i)
		if !fileExists(s.ErofsPath(digest)) {
			t.Errorf("image %d missing after build", i)
		}
		if _, err := s.ReadMeta(digest); err != nil {
			t.Errorf("meta %d: %v", i, err)
		}
	}
}

// Crash-litter cleanup is digest-scoped and lock-aware: building digest A
// must not remove an in-flight temp for digest B.
func TestCleanDigestLitterScoped(t *testing.T) {
	s := NewStore(t.TempDir())
	a := digestFile("sha256:"+strings.Repeat("a", 64)) + ".erofs"
	b := digestFile("sha256:"+strings.Repeat("b", 64)) + ".erofs"
	for _, n := range []string{a + ".12345.tmp", b + ".99999.tmp"} {
		if err := os.WriteFile(filepath.Join(s.root, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s.cleanDigestLitter("sha256:" + strings.Repeat("a", 64))
	for _, n := range []string{a + ".12345.tmp"} {
		if fileExists(filepath.Join(s.root, n)) {
			t.Errorf("stale temp %s survived digest-scoped cleanup", n)
		}
	}
	if !fileExists(filepath.Join(s.root, b+".99999.tmp")) {
		t.Error("another digest's live temp was deleted")
	}
}

// Cached image content and metadata are private (review finding 6):
// 0700 dirs, 0600 files.
func TestStorePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	s := NewStore(t.TempDir())
	digest := "sha256:" + strings.Repeat("c", 64)
	if _, err := s.ensure(digest, func(outPath string) (*Meta, error) {
		if err := os.WriteFile(outPath, []byte("img"), 0o600); err != nil {
			return nil, err
		}
		return &Meta{Ref: "registry.test/img:latest", Digest: digest, Arch: "arm64"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	mode := func(path string) os.FileMode {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return st.Mode().Perm()
	}
	if m := mode(s.root); m != 0o700 {
		t.Errorf("store root mode %o, want 700", m)
	}
	for _, p := range []string{s.ErofsPath(digest), s.metaPath(digest), filepath.Join(s.root, "index.json")} {
		if m := mode(p); m != 0o600 {
			t.Errorf("%s mode %o, want 600", filepath.Base(p), m)
		}
	}
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
