//go:build linux || darwin || windows

package sharefs

import (
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

const (
	// Node retention is already capped by maxLiveNodes. Path aliases need a
	// separate bound because hard links can give one inode many names.
	maxCoherencePaths     = 2 * maxLiveNodes
	maxCoherencePathBytes = 16 << 20
)

type shareWatchEvent struct {
	rel            string
	relTo          string // paired rename destination (Linux); empty when unpaired
	rename         bool
	invalidateDirs bool
	loss           error
}

// shareWatcher reports recursive host changes. Linux implements recursion
// lazily by watching only directories for which the guest can hold cache;
// Darwin and Windows use their native recursive facilities.
type shareWatcher interface {
	WatchDirectory(rel string) error
	ForgetDirectory(rel string)
	Reset() error
	Close() error
}

// coherencePath records which inode a guest-visible path resolved to. The
// generation separates mappings recorded before a rename pass from fresh
// ones remembered while that pass is still in flight.
type coherencePath struct {
	inode *fs.Inode
	gen   uint64
}

type exportCoherence struct {
	export *Export

	healthy atomic.Bool
	closed  atomic.Bool
	eventMu sync.Mutex

	mu         sync.RWMutex
	root       *fs.Inode
	paths      map[string]coherencePath
	reverse    map[*fs.Inode]map[string]struct{}
	pathBytes  int
	generation uint64
	watcher    shareWatcher
	watchErr   error
}

func newExportCoherence(export *Export) *exportCoherence {
	c := &exportCoherence{
		export:  export,
		paths:   make(map[string]coherencePath),
		reverse: make(map[*fs.Inode]map[string]struct{}),
	}
	watcher, err := newPlatformShareWatcher(export, c.handleWatchEvent)
	if err != nil {
		c.watchErr = err
		fmt.Fprintf(os.Stderr, "sharefs: cache watcher for %q unavailable; using %s metadata TTL: %v\n",
			export.Tag, descendantMetadataTTL, err)
		return c // the 100 ms fallback remains active
	}
	c.watcher = watcher
	c.healthy.Store(true)
	return c
}

func (c *exportCoherence) Healthy() bool {
	return c != nil && c.healthy.Load() && !c.closed.Load()
}

func (c *exportCoherence) attachRoot(root *fs.Inode) {
	if c == nil || root == nil {
		return
	}
	c.mu.Lock()
	c.root = root
	c.addPathLocked("", root)
	c.mu.Unlock()
}

func (c *exportCoherence) addPathLocked(rel string, inode *fs.Inode) bool {
	return c.addPathGenLocked(rel, inode, c.generation)
}

func (c *exportCoherence) addPathGenLocked(rel string, inode *fs.Inode, gen uint64) bool {
	if inode == nil {
		return true
	}
	if existing := c.paths[rel]; existing.inode == inode {
		return true
	} else if existing.inode != nil {
		c.removePathLocked(rel, existing.inode)
	}
	if len(c.paths) >= maxCoherencePaths || c.pathBytes+len(rel) > maxCoherencePathBytes {
		return false
	}
	c.paths[rel] = coherencePath{inode: inode, gen: gen}
	aliases := c.reverse[inode]
	if aliases == nil {
		aliases = make(map[string]struct{})
		c.reverse[inode] = aliases
	}
	aliases[rel] = struct{}{}
	c.pathBytes += len(rel)
	return true
}

func (c *exportCoherence) removePathLocked(rel string, inode *fs.Inode) {
	p, ok := c.paths[rel]
	if !ok || p.inode != inode {
		return
	}
	delete(c.paths, rel)
	c.pathBytes -= len(rel)
	aliases := c.reverse[inode]
	delete(aliases, rel)
	if len(aliases) == 0 {
		delete(c.reverse, inode)
	}
}

func cleanCoherenceRel(rel string) (string, bool) {
	rel = strings.ReplaceAll(rel, "\\", "/")
	rel = path.Clean(rel)
	if rel == "." {
		return "", true
	}
	if rel == ".." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "/") {
		return "", false
	}
	return rel, true
}

func joinCoherenceRel(parent, name string) (string, bool) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return "", false
	}
	if parent == "" {
		return name, true
	}
	return parent + "/" + name, true
}

// remember runs before a cacheable LOOKUP/READDIRPLUS response is returned.
// On Linux, installing the corresponding inotify watch synchronously closes
// the race between making a directory cacheable and monitoring it.
func (c *exportCoherence) remember(parent *fs.Inode, name string, child *fs.Inode) {
	if c == nil || child == nil || !c.Healthy() {
		return
	}
	c.mu.Lock()
	parentAliases := c.reverse[parent]
	var rel string
	found := false
	for parentRel := range parentAliases {
		if candidate, ok := joinCoherenceRel(parentRel, name); ok {
			rel, found = candidate, true
			break
		}
	}
	if !found {
		c.mu.Unlock()
		return
	}
	bounded := c.addPathLocked(rel, child)
	c.mu.Unlock()
	if !bounded {
		c.lose(fmt.Errorf("coherence path budget exceeded"))
		return
	}
	if child.Mode()&syscall.S_IFMT == syscall.S_IFDIR && c.watcher != nil {
		if err := c.watcher.WatchDirectory(rel); err != nil {
			c.lose(fmt.Errorf("watch directory %q: %w", rel, err))
		}
	}
}

func (c *exportCoherence) forget(inode *fs.Inode) {
	if c == nil || inode == nil {
		return
	}
	c.mu.Lock()
	aliases := c.reverse[inode]
	dirs := inode.Mode()&syscall.S_IFMT == syscall.S_IFDIR
	paths := make([]string, 0, len(aliases))
	for rel := range aliases {
		paths = append(paths, rel)
		c.removePathLocked(rel, inode)
	}
	if c.root == inode {
		c.root = nil
	}
	c.mu.Unlock()
	if dirs && c.watcher != nil {
		for _, rel := range paths {
			c.watcher.ForgetDirectory(rel)
		}
	}
}

func (c *exportCoherence) forgetPath(parent *fs.Inode, name string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	for parentRel := range c.reverse[parent] {
		rel, ok := joinCoherenceRel(parentRel, name)
		if !ok {
			continue
		}
		p := c.paths[rel]
		if p.inode != nil {
			c.removePathLocked(rel, p.inode)
		}
	}
	c.mu.Unlock()
}

// renamePath updates the advisory path index for a guest-originated rename.
// Native watcher events still perform the kernel invalidation; the guest VFS
// already invalidates its own operation synchronously.
func (c *exportCoherence) renamePath(oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	var oldRel, newRel string
	for parentRel := range c.reverse[oldParent] {
		oldRel, _ = joinCoherenceRel(parentRel, oldName)
		break
	}
	for parentRel := range c.reverse[newParent] {
		newRel, _ = joinCoherenceRel(parentRel, newName)
		break
	}
	if oldRel == "" || newRel == "" || oldRel == newRel {
		c.mu.Unlock()
		return
	}
	updates := make(map[string]coherencePath)
	for rel, p := range c.paths {
		if rel == oldRel || strings.HasPrefix(rel, oldRel+"/") {
			updates[newRel+strings.TrimPrefix(rel, oldRel)] = p
			c.removePathLocked(rel, p.inode)
		}
	}
	bounded := true
	for rel, p := range updates {
		bounded = c.addPathGenLocked(rel, p.inode, p.gen) && bounded
	}
	c.mu.Unlock()
	if !bounded {
		c.lose(fmt.Errorf("coherence path budget exceeded after rename"))
	}
}

func (c *exportCoherence) handleWatchEvent(event shareWatchEvent) {
	if c == nil || c.closed.Load() || !c.healthy.Load() {
		return
	}
	c.eventMu.Lock()
	defer c.eventMu.Unlock()
	if c.closed.Load() || !c.healthy.Load() {
		return
	}
	if event.loss != nil {
		invalidateShareDirCache(c.export)
		c.loseLocked(event.loss)
		return
	}
	rel, ok := cleanCoherenceRel(event.rel)
	if !ok {
		c.loseLocked(fmt.Errorf("watcher returned path outside export: %q", event.rel))
		return
	}
	var relTo string
	if event.relTo != "" {
		relTo, ok = cleanCoherenceRel(event.relTo)
		if !ok {
			c.loseLocked(fmt.Errorf("watcher returned rename target outside export: %q", event.relTo))
			return
		}
	}
	parentRel, name := path.Split(rel)
	parentRel = strings.TrimSuffix(parentRel, "/")
	c.mu.RLock()
	child := c.paths[rel].inode
	parent := c.paths[parentRel].inode
	if rel == "" {
		parent = c.root
	}
	c.mu.RUnlock()

	if event.rename {
		// Large recursive roots can receive unrelated host activity. If neither
		// the changed entry nor its direct parent is known to the guest, there is
		// no cache to invalidate and a global epoch bump would be destructive.
		if child == nil && parent == nil {
			return
		}
		invalidateShareDirCache(c.export)
		// Start a new mapping generation before notifications unblock guests:
		// a lookup that races with this pass reflects post-rename reality, and
		// the stale-mapping sweep at the end must not destroy it again.
		c.mu.Lock()
		c.generation++
		c.mu.Unlock()
		// Emit the most specific entry invalidation available before the global
		// epoch bump. Recursive watchers do not consistently provide paired
		// old/new paths, so the epoch remains the bounded unambiguous fallback.
		if name != "" && parent != nil {
			if errno := parent.NotifyEntry(name); !benignNotifyErr(errno) {
				c.loseLocked(fmt.Errorf("invalidate renamed entry %q: %v", rel, errno))
				return
			}
		}
		if relTo != "" {
			toParentRel, toName := path.Split(relTo)
			toParentRel = strings.TrimSuffix(toParentRel, "/")
			c.mu.RLock()
			toParent := c.paths[toParentRel].inode
			c.mu.RUnlock()
			if toName != "" && toParent != nil {
				if errno := toParent.NotifyEntry(toName); !benignNotifyErr(errno) {
					c.loseLocked(fmt.Errorf("invalidate rename target %q: %v", relTo, errno))
					return
				}
			}
		}
		if c.watcher != nil {
			if err := c.watcher.Reset(); err != nil {
				c.loseLocked(fmt.Errorf("reset watcher after rename: %w", err))
				return
			}
		}
		c.flushAllLocked()
		c.clearDescendantPaths()
		return
	}

	if child == nil && parent == nil {
		return
	}
	if event.invalidateDirs {
		invalidateShareDirCache(c.export)
	}

	if name != "" && parent != nil {
		if errno := parent.NotifyEntry(name); !benignNotifyErr(errno) {
			c.loseLocked(fmt.Errorf("invalidate entry %q: %v", rel, errno))
			return
		}
	}
	if child != nil {
		if errno := child.NotifyContent(0, 0); !benignNotifyErr(errno) {
			c.loseLocked(fmt.Errorf("invalidate inode %q: %v", rel, errno))
			return
		}
	} else if rel == "" && parent != nil {
		if errno := parent.NotifyContent(0, 0); !benignNotifyErr(errno) {
			c.loseLocked(fmt.Errorf("invalidate export root: %v", errno))
		}
	}
}

func benignNotifyErr(errno syscall.Errno) bool {
	return errno == 0 || fuse.Status(errno) == fuse.ENOENT
}

// clearDescendantPaths drops path mappings recorded before the current
// generation: after a rename they may resolve to a different host object.
// Mappings remembered while the rename pass was in flight belong to the new
// generation, reflect post-rename reality, and stay valid.
func (c *exportCoherence) clearDescendantPaths() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for rel, p := range c.paths {
		if p.gen < c.generation {
			c.removePathLocked(rel, p.inode)
		}
	}
	if c.root != nil {
		c.addPathLocked("", c.root)
	}
}

func (c *exportCoherence) snapshotNodes() []*fs.Inode {
	c.mu.RLock()
	nodes := make([]*fs.Inode, 0, len(c.reverse))
	for inode := range c.reverse {
		nodes = append(nodes, inode)
	}
	c.mu.RUnlock()
	return nodes
}

func (c *exportCoherence) flushAllLocked() {
	if c.export == nil || c.export.hub == nil || !c.export.hub.notificationsReady.Load() {
		return
	}
	status := c.export.hub.protocol.GantryNotifyEpoch()
	if status == fuse.ENOSYS {
		return // notification queue became ready before FUSE_INIT; no long TTL was served
	}
	if status != fuse.OK && status != fuse.ENOENT {
		c.export.hub.guard.fail(fmt.Errorf("notify epoch: %v", status))
		return
	}
	for _, inode := range c.snapshotNodes() {
		if errno := inode.NotifyContent(0, 0); !benignNotifyErr(errno) {
			c.export.hub.guard.fail(fmt.Errorf("invalidate known inode: %v", errno))
			return
		}
	}
}

func (c *exportCoherence) lose(err error) {
	if c == nil {
		return
	}
	c.eventMu.Lock()
	defer c.eventMu.Unlock()
	c.loseLocked(err)
}

func (c *exportCoherence) revoke() {
	if c == nil {
		return
	}
	c.eventMu.Lock()
	defer c.eventMu.Unlock()
	if c.healthy.CompareAndSwap(true, false) {
		c.flushAllLocked()
	}
}

func (c *exportCoherence) loseLocked(err error) {
	if !c.healthy.CompareAndSwap(true, false) {
		return
	}
	c.flushAllLocked()
	if c.export != nil && c.export.hub != nil && c.export.hub.debugFS {
		fmt.Printf("sharefs: cache watcher for %q degraded to %s: %v\n", c.export.Tag, descendantMetadataTTL, err)
	}
}

func (c *exportCoherence) close() {
	if c == nil || !c.closed.CompareAndSwap(false, true) {
		return
	}
	c.healthy.Store(false)
	if c.watcher != nil {
		_ = c.watcher.Close()
	}
	c.mu.Lock()
	clear(c.paths)
	clear(c.reverse)
	c.root = nil
	c.pathBytes = 0
	c.mu.Unlock()
}
