//go:build linux || darwin

package sharefs

import (
	"container/list"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestShareDirCacheIsBoundedAndUsesIndependentOpens(t *testing.T) {
	root := t.TempDir()
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close() }()
	cache := &shareDirCache{entries: make(map[uint64]*list.Element)}
	defer cache.close()

	for index := 0; index < maxCachedShareDirs+16; index++ {
		name := fmt.Sprintf("d%03d", index)
		if err := os.Mkdir(root+"/"+name, 0o700); err != nil {
			t.Fatal(err)
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			t.Fatal(err)
		}
		cache.prefetch(uint64(index+1), int(parent.Fd()), name, uint64(stat.Ino))
	}
	if got := cache.lru.Len(); got != maxCachedShareDirs {
		t.Fatalf("cached directories = %d, want %d", got, maxCachedShareDirs)
	}
	if _, ok := cache.open(1); ok {
		t.Fatal("oldest directory survived cache bound")
	}
	key := uint64(maxCachedShareDirs + 16)
	first, ok := cache.open(key)
	if !ok {
		t.Fatal("newest directory missing from cache")
	}
	defer func() { _ = unix.Close(first) }()
	second, ok := cache.open(key)
	if !ok {
		t.Fatal("second independent open failed")
	}
	defer func() { _ = unix.Close(second) }()
	if first == second {
		t.Fatalf("cache reused descriptor %d instead of opening an independent directory description", first)
	}
}
