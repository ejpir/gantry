//go:build linux || darwin

package sharefs

import (
	"container/list"
	"sync"

	"golang.org/x/sys/unix"
)

// maxCachedShareDirs bounds trusted directory capabilities independently of
// guest FUSE handles. READDIRPLUS normally prefetches at most one response
// page of children, so 128 entries cover several levels of a depth-first walk
// without turning a large export into an unbounded host-FD cache.
const maxCachedShareDirs = 128

type cachedShareDir struct {
	key uint64
	fd  int
}

type shareDirCache struct {
	mu      sync.Mutex
	entries map[uint64]*list.Element
	lru     list.List
	closed  bool
}

var shareDirCaches sync.Map // map[*Export]*shareDirCache

func registerShareDirCache(export *Export) {
	if export == nil {
		return
	}
	shareDirCaches.Store(export, &shareDirCache{entries: make(map[uint64]*list.Element)})
}

func closeShareDirCache(export *Export) {
	value, ok := shareDirCaches.LoadAndDelete(export)
	if !ok {
		return
	}
	value.(*shareDirCache).close()
}

func invalidateShareDirCache(export *Export) {
	shareDirectoryCache(export).clear()
}

func shareDirectoryCache(export *Export) *shareDirCache {
	value, ok := shareDirCaches.Load(export)
	if !ok {
		return nil
	}
	return value.(*shareDirCache)
}

// prefetch pins a child directory relative to the directory handle that
// supplied its READDIRPLUS entry. Fstat verifies that an external rename race
// did not swap the child between LOOKUP and openat.
func (c *shareDirCache) prefetch(key uint64, parentFD int, name string, expectedIno uint64) {
	if c == nil || key == 0 || parentFD < 0 || name == "" {
		return
	}
	fd, err := unix.Openat(parentFD, name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || uint64(stat.Ino) != expectedIno || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(fd)
		return
	}
	c.insert(key, fd)
}

func (c *shareDirCache) insert(key uint64, fd int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = unix.Close(fd)
		return
	}
	if element := c.entries[key]; element != nil {
		c.lru.MoveToFront(element)
		_ = unix.Close(fd)
		return
	}
	element := c.lru.PushFront(cachedShareDir{key: key, fd: fd})
	c.entries[key] = element
	for c.lru.Len() > maxCachedShareDirs {
		oldest := c.lru.Back()
		entry := oldest.Value.(cachedShareDir)
		delete(c.entries, entry.key)
		c.lru.Remove(oldest)
		_ = unix.Close(entry.fd)
	}
}

// open returns a new open file description so each FUSE directory handle has
// independent getdents offsets; dup(2) would incorrectly share the cache
// entry's offset.
func (c *shareDirCache) open(key uint64) (int, bool) {
	if c == nil || key == 0 {
		return -1, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	element := c.entries[key]
	if c.closed || element == nil {
		return -1, false
	}
	entry := element.Value.(cachedShareDir)
	fd, err := unix.Openat(entry.fd, ".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		delete(c.entries, entry.key)
		c.lru.Remove(element)
		_ = unix.Close(entry.fd)
		return -1, false
	}
	c.lru.MoveToFront(element)
	return fd, true
}

func (c *shareDirCache) clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for element := c.lru.Front(); element != nil; element = element.Next() {
		_ = unix.Close(element.Value.(cachedShareDir).fd)
	}
	clear(c.entries)
	c.lru.Init()
}

func (c *shareDirCache) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	for element := c.lru.Front(); element != nil; element = element.Next() {
		_ = unix.Close(element.Value.(cachedShareDir).fd)
	}
	clear(c.entries)
	c.lru.Init()
}
