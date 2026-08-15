//go:build linux || darwin

package sharefs

import (
	"container/list"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	// Directory capabilities are split between a small recency window for
	// the active traversal stack and a protected set for frequently used or
	// wide parents. This keeps the descriptor bound unchanged from the old
	// child-prefetch cache while letting one parent capability serve every
	// child in a directory.
	maxCachedShareDirParents    = 128
	maxRecentShareDirParents    = 32
	maxProtectedShareDirParents = maxCachedShareDirParents - maxRecentShareDirParents
	promoteShareDirParentAt     = 8

	// Recipes contain no descriptors. The bound prevents a malicious guest
	// from retaining unbounded names by issuing READDIRPLUS without opening
	// the returned directories; it still covers substantially wider trees
	// than the descriptor-per-child design.
	maxCachedShareDirRecipes = 65536
)

type cachedShareDir struct {
	key         uint64
	parentKey   uint64
	name        string
	expectedIno uint64
}

type cachedShareDirParent struct {
	key       uint64
	fd        int
	hits      uint32
	protected bool
	element   *list.Element
	children  map[uint64]struct{}
}

type shareDirCache struct {
	mu           sync.Mutex
	entries      map[uint64]cachedShareDir
	parents      map[uint64]*cachedShareDirParent
	recent       list.List
	protected    list.List
	statsEnabled bool
	stats        shareDirCacheStats
	closed       bool
}

type shareDirCacheStats struct {
	prefetches      uint64
	rejected        uint64
	parentOpens     uint64
	parentEvictions uint64
	openHits        uint64
	openMisses      uint64
}

var shareDirCaches sync.Map // map[*Export]*shareDirCache

func registerShareDirCache(export *Export) {
	if export == nil {
		return
	}
	shareDirCaches.Store(export, &shareDirCache{
		entries:      make(map[uint64]cachedShareDir),
		parents:      make(map[uint64]*cachedShareDirParent),
		statsEnabled: os.Getenv("GANTRY_VHOST_STATS") == "1",
	})
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

// prefetch records how to open a child directory relative to the directory
// handle that supplied its READDIRPLUS entry. Unlike the old cache, it pins
// the parent once instead of opening and retaining every child. Opening a
// child later takes one openat plus one identity check regardless of its
// depth beneath the export root.
func (c *shareDirCache) prefetch(key, parentKey uint64, parentFD int, name string, expectedIno uint64) bool {
	if c == nil || key == 0 || parentKey == 0 || parentFD < 0 || name == "" || name == "." || name == ".." ||
		strings.ContainsRune(name, '/') || strings.ContainsRune(name, '\x00') {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.initLocked()
	c.stats.prefetches++
	if _, exists := c.entries[key]; !exists && len(c.entries) >= maxCachedShareDirRecipes {
		c.stats.rejected++
		return false
	}

	parent := c.parents[parentKey]
	if parent == nil {
		fd, err := unix.Openat(parentFD, ".",
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return false
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = unix.Close(fd)
			return false
		}
		parent = &cachedShareDirParent{
			key:      parentKey,
			fd:       fd,
			children: make(map[uint64]struct{}),
		}
		parent.element = c.recent.PushBack(parent)
		c.parents[parentKey] = parent
		c.stats.parentOpens++
		c.trimRecentLocked()
		// trimRecentLocked can only evict an older entry: the new parent is
		// at the back of the list.
	}

	if old, exists := c.entries[key]; exists {
		if old.parentKey != parentKey || old.name != name || old.expectedIno != expectedIno {
			c.removeRecipeLocked(key)
		} else {
			c.noteParentLocked(parent)
			return true
		}
	}
	c.entries[key] = cachedShareDir{
		key: key, parentKey: parentKey, name: strings.Clone(name), expectedIno: expectedIno,
	}
	parent.children[key] = struct{}{}
	c.noteParentLocked(parent)
	return true
}

func (c *shareDirCache) initLocked() {
	if c.entries == nil {
		c.entries = make(map[uint64]cachedShareDir)
	}
	if c.parents == nil {
		c.parents = make(map[uint64]*cachedShareDirParent)
	}
}

func (c *shareDirCache) noteParentLocked(parent *cachedShareDirParent) {
	if parent == nil {
		return
	}
	if parent.hits < math.MaxUint32 {
		parent.hits++
	}
	if parent.protected {
		return
	}
	c.recent.MoveToBack(parent.element)
	if parent.hits < promoteShareDirParentAt {
		return
	}
	if c.protected.Len() >= maxProtectedShareDirParents {
		victim := c.leastProtectedLocked()
		if victim == nil || victim.hits >= parent.hits {
			return
		}
		c.evictParentLocked(victim)
	}
	c.recent.Remove(parent.element)
	parent.protected = true
	parent.element = c.protected.PushBack(parent)
}

func (c *shareDirCache) leastProtectedLocked() *cachedShareDirParent {
	var victim *cachedShareDirParent
	for element := c.protected.Front(); element != nil; element = element.Next() {
		candidate := element.Value.(*cachedShareDirParent)
		if victim == nil || candidate.hits < victim.hits {
			victim = candidate
		}
	}
	return victim
}

func (c *shareDirCache) trimRecentLocked() {
	for c.recent.Len() > maxRecentShareDirParents {
		c.evictParentLocked(c.recent.Front().Value.(*cachedShareDirParent))
	}
}

func (c *shareDirCache) removeRecipeLocked(key uint64) {
	entry, ok := c.entries[key]
	if !ok {
		return
	}
	delete(c.entries, key)
	if parent := c.parents[entry.parentKey]; parent != nil {
		delete(parent.children, key)
	}
}

func (c *shareDirCache) evictParentLocked(parent *cachedShareDirParent) {
	if parent == nil || c.parents[parent.key] != parent {
		return
	}
	if parent.protected {
		c.protected.Remove(parent.element)
	} else {
		c.recent.Remove(parent.element)
	}
	delete(c.parents, parent.key)
	c.stats.parentEvictions++
	for key := range parent.children {
		if entry, ok := c.entries[key]; ok && entry.parentKey == parent.key {
			delete(c.entries, key)
		}
	}
	_ = unix.Close(parent.fd)
}

// open retains a child's recipe so every READDIR page, including the final
// EOF probe, can use the same verified parent capability. Holding c.mu across
// openat prevents concurrent invalidation from closing the parent descriptor
// before the kernel resolves the child. FORGET, watcher invalidation and
// parent eviction bound the recipe lifetime.
func (c *shareDirCache) open(key uint64) (int, bool) {
	if c == nil || key == 0 {
		return -1, false
	}
	c.mu.Lock()
	entry, ok := c.entries[key]
	if c.closed || !ok {
		c.recordOpenLocked(false)
		c.mu.Unlock()
		return -1, false
	}
	parent := c.parents[entry.parentKey]
	if parent == nil {
		c.recordOpenLocked(false)
		c.mu.Unlock()
		return -1, false
	}
	if !parent.protected {
		c.recent.MoveToBack(parent.element)
	}
	fd, err := unix.Openat(parent.fd, entry.name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	c.mu.Unlock()
	if err != nil {
		c.removeRecipeIfUnchanged(entry)
		c.recordOpen(false)
		return -1, false
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || uint64(stat.Ino) != entry.expectedIno || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(fd)
		c.removeRecipeIfUnchanged(entry)
		c.recordOpen(false)
		return -1, false
	}
	c.recordOpen(true)
	return fd, true
}

func (c *shareDirCache) removeRecipeIfUnchanged(expected cachedShareDir) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if current, ok := c.entries[expected.key]; ok && current == expected {
		c.removeRecipeLocked(expected.key)
	}
}

func (c *shareDirCache) recordOpen(hit bool) {
	if c == nil || !c.statsEnabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recordOpenLocked(hit)
}

func (c *shareDirCache) recordOpenLocked(hit bool) {
	if !c.statsEnabled {
		return
	}
	if hit {
		c.stats.openHits++
	} else {
		c.stats.openMisses++
	}
	if attempts := c.stats.openHits + c.stats.openMisses; attempts%10000 == 0 {
		c.logStatsLocked()
	}
}

func (c *shareDirCache) logStatsLocked() {
	fmt.Fprintf(os.Stderr,
		"share-dir-cache-stats: prefetches=%d rejected=%d parent-opens=%d parent-evictions=%d open-hits=%d open-misses=%d recipes=%d parents=%d\n",
		c.stats.prefetches, c.stats.rejected, c.stats.parentOpens, c.stats.parentEvictions,
		c.stats.openHits, c.stats.openMisses, len(c.entries), len(c.parents))
}

func (c *shareDirCache) forget(key uint64) {
	if c == nil || key == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeRecipeLocked(key)
	if parent := c.parents[key]; parent != nil {
		c.evictParentLocked(parent)
	}
}

func (c *shareDirCache) clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearLocked()
}

func (c *shareDirCache) clearLocked() {
	for _, parent := range c.parents {
		_ = unix.Close(parent.fd)
	}
	clear(c.entries)
	clear(c.parents)
	c.recent.Init()
	c.protected.Init()
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
	if c.statsEnabled {
		c.logStatsLocked()
	}
	c.clearLocked()
}
