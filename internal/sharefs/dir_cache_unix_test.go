//go:build linux || darwin

package sharefs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func newTestShareDirCache() *shareDirCache {
	return &shareDirCache{
		entries: make(map[uint64]cachedShareDir),
		parents: make(map[uint64]*cachedShareDirParent),
	}
}

func testDirIno(t *testing.T, parentFD int, name string) uint64 {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	return uint64(stat.Ino)
}

func TestShareDirCacheUsesOneParentForWideDirectory(t *testing.T) {
	root := t.TempDir()
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close() }()
	cache := newTestShareDirCache()
	defer cache.close()

	const children = maxCachedShareDirParents * 2
	inodes := make([]uint64, children)
	for index := range children {
		name := fmt.Sprintf("d%03d", index)
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
		inodes[index] = testDirIno(t, int(parent.Fd()), name)
		if !cache.prefetch(uint64(index+1), 9001, int(parent.Fd()), name, inodes[index]) {
			t.Fatalf("prefetch child %d rejected", index)
		}
	}
	if got := len(cache.parents); got != 1 {
		t.Fatalf("cached parent descriptors = %d, want 1", got)
	}
	if got := len(cache.entries); got != children {
		t.Fatalf("cached child recipes = %d, want %d", got, children)
	}
	if got := cache.protected.Len(); got != 1 {
		t.Fatalf("protected parents = %d, want wide parent promoted", got)
	}

	for index := range children {
		fd, ok := cache.open(uint64(index + 1))
		if !ok {
			t.Fatalf("open child %d failed", index)
		}
		_ = unix.Close(fd)
	}
	if got := len(cache.entries); got != children {
		t.Fatalf("retained child recipes = %d, want %d", got, children)
	}
	if fd, ok := cache.open(1); !ok {
		t.Fatal("second directory page could not reuse child recipe")
	} else {
		_ = unix.Close(fd)
	}
	if got := len(cache.parents); got != 1 {
		t.Fatalf("parent descriptor disappeared after child opens: got %d parents", got)
	}
	cache.forget(1)
	if fd, ok := cache.open(1); ok {
		_ = unix.Close(fd)
		t.Fatal("forgotten child recipe remained cached")
	}
}

func TestShareDirCacheVerifiesChildIdentity(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close() }()
	cache := newTestShareDirCache()
	defer cache.close()

	ino := testDirIno(t, int(parent.Fd()), "child")
	if !cache.prefetch(1, 2, int(parent.Fd()), "child", ino+1) {
		t.Fatal("prefetch rejected identity-mismatch test recipe")
	}
	if fd, ok := cache.open(1); ok {
		_ = unix.Close(fd)
		t.Fatal("opened a child whose inode no longer matched READDIRPLUS")
	}
	if !cache.prefetch(1, 2, int(parent.Fd()), "child", ino) {
		t.Fatal("prefetch rejected valid child")
	}
	if fd, ok := cache.open(1); !ok {
		t.Fatal("valid child failed identity check")
	} else {
		_ = unix.Close(fd)
	}
}

func TestShareDirCacheRejectsNonComponentNames(t *testing.T) {
	root := t.TempDir()
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close() }()
	cache := newTestShareDirCache()
	defer cache.close()
	for index, name := range []string{"", ".", "..", "a/b", "a\x00b"} {
		if cache.prefetch(uint64(index+1), 9001, int(parent.Fd()), name, 1) {
			t.Fatalf("unsafe child name %q entered cache", name)
		}
	}
	if len(cache.parents) != 0 || len(cache.entries) != 0 {
		t.Fatalf("rejected names allocated cache state: parents=%d recipes=%d", len(cache.parents), len(cache.entries))
	}
}

func TestShareDirCacheInvalidationClosesParentsAndRecipes(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close() }()
	cache := newTestShareDirCache()
	defer cache.close()
	if !cache.prefetch(1, 2, int(parent.Fd()), "child", testDirIno(t, int(parent.Fd()), "child")) {
		t.Fatal("prefetch failed")
	}
	cachedFD := cache.parents[2].fd

	cache.clear()
	var stat unix.Stat_t
	if err := unix.Fstat(cachedFD, &stat); !errors.Is(err, unix.EBADF) {
		t.Fatalf("invalidated parent descriptor remained open: %v", err)
	}
	if len(cache.parents) != 0 || len(cache.entries) != 0 || cache.recent.Len() != 0 || cache.protected.Len() != 0 {
		t.Fatalf("cache retained state after invalidation: parents=%d recipes=%d recent=%d protected=%d",
			len(cache.parents), len(cache.entries), cache.recent.Len(), cache.protected.Len())
	}
	if fd, ok := cache.open(1); ok {
		_ = unix.Close(fd)
		t.Fatal("invalidated recipe remained usable")
	}
}

func TestShareDirCacheProtectsWideParentFromRecentChurn(t *testing.T) {
	root := t.TempDir()
	widePath := filepath.Join(root, "wide")
	if err := os.Mkdir(widePath, 0o700); err != nil {
		t.Fatal(err)
	}
	wide, err := os.Open(widePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wide.Close() }()
	cache := newTestShareDirCache()
	defer cache.close()

	for index := range promoteShareDirParentAt {
		name := fmt.Sprintf("child%02d", index)
		if err := os.Mkdir(filepath.Join(widePath, name), 0o700); err != nil {
			t.Fatal(err)
		}
		if !cache.prefetch(uint64(index+1), 5000, int(wide.Fd()), name, testDirIno(t, int(wide.Fd()), name)) {
			t.Fatalf("wide prefetch %d failed", index)
		}
	}
	if parent := cache.parents[5000]; parent == nil || !parent.protected {
		t.Fatal("wide parent was not promoted")
	}

	for index := range maxRecentShareDirParents * 2 {
		parentPath := filepath.Join(root, fmt.Sprintf("narrow%03d", index))
		if err := os.Mkdir(parentPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(parentPath, "child"), 0o700); err != nil {
			t.Fatal(err)
		}
		parent, err := os.Open(parentPath)
		if err != nil {
			t.Fatal(err)
		}
		key := uint64(10000 + index)
		admitted := cache.prefetch(key, key+10000, int(parent.Fd()), "child", testDirIno(t, int(parent.Fd()), "child"))
		_ = parent.Close()
		if !admitted {
			t.Fatalf("narrow prefetch %d failed", index)
		}
	}
	if cache.parents[5000] == nil {
		t.Fatal("recent-parent churn evicted the protected wide parent")
	}
	if fd, ok := cache.open(1); !ok {
		t.Fatal("wide parent's child recipe was lost during recent churn")
	} else {
		_ = unix.Close(fd)
	}
	if cache.recent.Len() > maxRecentShareDirParents || cache.protected.Len() > maxProtectedShareDirParents {
		t.Fatalf("parent tiers exceeded bounds: recent=%d protected=%d", cache.recent.Len(), cache.protected.Len())
	}
}

func TestShareDirCacheRecipeLimit(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close() }()
	cache := newTestShareDirCache()
	defer cache.close()
	ino := testDirIno(t, int(parent.Fd()), "child")
	for index := range maxCachedShareDirRecipes {
		if !cache.prefetch(uint64(index+1), 9001, int(parent.Fd()), "child", ino) {
			t.Fatalf("recipe %d rejected before bound", index)
		}
	}
	if cache.prefetch(maxCachedShareDirRecipes+1, 9001, int(parent.Fd()), "child", ino) {
		t.Fatal("recipe admitted beyond bound")
	}
	if got := len(cache.entries); got != maxCachedShareDirRecipes {
		t.Fatalf("recipes = %d, want %d", got, maxCachedShareDirRecipes)
	}
}

func TestShareDirCacheConcurrentPrefetchSharesParent(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close() }()
	cache := newTestShareDirCache()
	defer cache.close()
	ino := testDirIno(t, int(parent.Fd()), "child")

	const workers = 256
	start := make(chan struct{})
	results := make(chan bool, workers)
	var group sync.WaitGroup
	for index := range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- cache.prefetch(uint64(index+1), 9001, int(parent.Fd()), "child", ino)
		}()
	}
	close(start)
	group.Wait()
	close(results)
	for admitted := range results {
		if !admitted {
			t.Fatal("concurrent prefetch unexpectedly rejected")
		}
	}
	if got := len(cache.parents); got != 1 {
		t.Fatalf("concurrent prefetch created %d parent descriptors, want 1", got)
	}
	if got := len(cache.entries); got != workers {
		t.Fatalf("concurrent recipes = %d, want %d", got, workers)
	}
}
