package image

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// Concurrent builds of DIFFERENT digests must not lose each other's
// index entries or delete each other's temp files (review finding 4:
// the store used one shared index.json.tmp and deleted every *.erofs.tmp
// before taking any lock).
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
	for _, n := range []string{a + ".12345.tmp", a + ".tmp", b + ".99999.tmp"} {
		if err := os.WriteFile(filepath.Join(s.root, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s.cleanDigestLitter("sha256:" + strings.Repeat("a", 64))
	for _, n := range []string{a + ".12345.tmp", a + ".tmp"} {
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

	// migration: pre-hardening 0644/0755 caches are tightened on use
	if err := os.Chmod(s.ErofsPath(digest), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ensure(digest, nil); err != nil { // cached path: no build
		t.Fatal(err)
	}
	if m := mode(s.ErofsPath(digest)); m != 0o600 {
		t.Errorf("legacy 0644 image not tightened, mode %o", m)
	}
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
