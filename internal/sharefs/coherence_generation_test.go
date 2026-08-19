//go:build linux || darwin || windows

package sharefs

import (
	"context"
	"sync"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestCoherenceSameInodeLookupRefreshesGeneration(t *testing.T) {
	inode := &fs.Inode{}
	c := &exportCoherence{
		paths:   make(map[string]coherencePath),
		reverse: make(map[*fs.Inode]map[string]struct{}),
	}
	if !c.addPathGenLocked("file", inode, 1) {
		t.Fatal("initial mapping was rejected")
	}
	c.generation = 2
	if !c.addPathLocked("file", inode) {
		t.Fatal("fresh mapping was rejected")
	}
	if got := c.paths["file"].gen; got != 2 {
		t.Fatalf("refreshed mapping generation = %d, want 2", got)
	}

	c.clearDescendantPaths()
	if got := c.paths["file"].inode; got != inode {
		t.Fatal("post-rename sweep removed a freshly confirmed mapping")
	}
}

type resetBarrierWatcher struct {
	resetStarted chan struct{}
	allowReset   chan struct{}
	resetOnce    sync.Once
}

func (w *resetBarrierWatcher) WatchDirectory(string) error { return nil }
func (w *resetBarrierWatcher) ForgetDirectory(string)      {}
func (w *resetBarrierWatcher) Close() error                { return nil }

func (w *resetBarrierWatcher) Reset() error {
	w.resetOnce.Do(func() { close(w.resetStarted) })
	<-w.allowReset
	return nil
}

func TestCoherenceRenameResetSerializesPathMappings(t *testing.T) {
	watcher := &resetBarrierWatcher{
		resetStarted: make(chan struct{}),
		allowReset:   make(chan struct{}),
	}
	victim := &fs.Inode{}
	c := &exportCoherence{
		paths:   make(map[string]coherencePath),
		reverse: make(map[*fs.Inode]map[string]struct{}),
		watcher: watcher,
	}
	c.healthy.Store(true)
	c.addPathLocked("victim", victim)

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.handleWatchEvent(shareWatchEvent{rel: "victim", rename: true})
	}()
	<-watcher.resetStarted

	// Reset must exclude remember's path update until the stale watches have
	// been removed and the new generation has begun. Otherwise a lookup can
	// retain a new mapping backed only by a watch that Reset just discarded.
	if c.mu.TryLock() {
		c.mu.Unlock()
		close(watcher.allowReset)
		<-done
		t.Fatal("rename reset did not serialize coherence path mappings")
	}
	close(watcher.allowReset)
	<-done
	if c.generation != 1 {
		t.Fatalf("coherence generation = %d, want 1", c.generation)
	}
}

type coherenceTestNode struct{ fs.Inode }

func coherenceTestTree(t *testing.T) (*fs.Inode, *fs.Inode, *fs.Inode) {
	t.Helper()
	rootOps := &coherenceTestNode{}
	_ = fs.NewNodeFS(rootOps, nil)
	root := rootOps.EmbeddedInode()
	oldDir := root.NewPersistentInode(context.Background(), &coherenceTestNode{}, fs.StableAttr{Mode: fuse.S_IFDIR})
	newDir := root.NewPersistentInode(context.Background(), &coherenceTestNode{}, fs.StableAttr{Mode: fuse.S_IFDIR})
	return root, oldDir, newDir
}

type forgetBarrierWatcher struct {
	mu            sync.Mutex
	watched       map[string]bool
	forgetStarted chan struct{}
	allowForget   chan struct{}
	forgetOnce    sync.Once
}

func (w *forgetBarrierWatcher) WatchDirectory(rel string) error {
	w.mu.Lock()
	w.watched[rel] = true
	w.mu.Unlock()
	return nil
}

func (w *forgetBarrierWatcher) ForgetDirectory(rel string) {
	w.forgetOnce.Do(func() { close(w.forgetStarted) })
	<-w.allowForget
	w.mu.Lock()
	delete(w.watched, rel)
	w.mu.Unlock()
}

func (w *forgetBarrierWatcher) Reset() error { return nil }
func (w *forgetBarrierWatcher) Close() error { return nil }

func (w *forgetBarrierWatcher) isWatched(rel string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.watched[rel]
}

func TestCoherenceForgetSerializesReplacementWatch(t *testing.T) {
	root, oldDir, newDir := coherenceTestTree(t)
	watcher := &forgetBarrierWatcher{
		watched:       map[string]bool{"dir": true},
		forgetStarted: make(chan struct{}),
		allowForget:   make(chan struct{}),
	}
	c := &exportCoherence{
		paths:   make(map[string]coherencePath),
		reverse: make(map[*fs.Inode]map[string]struct{}),
		watcher: watcher,
	}
	c.healthy.Store(true)
	c.addPathLocked("", root)
	c.addPathLocked("dir", oldDir)

	forgot := make(chan struct{})
	go func() {
		c.forget(oldDir)
		close(forgot)
	}()
	<-watcher.forgetStarted

	// ForgetDirectory must still be inside the coherence critical section.
	// If this lock succeeds, a replacement mapping could install its watch
	// before the stale forget resumes and deletes that same path-keyed watch.
	if c.mu.TryLock() {
		c.mu.Unlock()
		close(watcher.allowForget)
		<-forgot
		t.Fatal("stale watch removal did not serialize coherence path mappings")
	}
	close(watcher.allowForget)
	<-forgot
	c.remember(root, "dir", newDir)

	if got := c.paths["dir"].inode; got != newDir {
		t.Fatalf("replacement path maps to %p, want %p", got, newDir)
	}
	if !watcher.isWatched("dir") {
		t.Fatal("replacement directory mapping has no watch")
	}
}

type recordingWatcher struct {
	forgot []string
}

func (*recordingWatcher) WatchDirectory(string) error { return nil }
func (w *recordingWatcher) ForgetDirectory(rel string) {
	w.forgot = append(w.forgot, rel)
}
func (*recordingWatcher) Reset() error { return nil }
func (*recordingWatcher) Close() error { return nil }

func TestCoherenceForgetPathRemovesDirectoryWatch(t *testing.T) {
	root, dir, _ := coherenceTestTree(t)
	watcher := &recordingWatcher{}
	c := &exportCoherence{
		paths:   make(map[string]coherencePath),
		reverse: make(map[*fs.Inode]map[string]struct{}),
		watcher: watcher,
	}
	c.addPathLocked("", root)
	c.addPathLocked("dir", dir)

	c.forgetPath(root, "dir")

	if _, exists := c.paths["dir"]; exists {
		t.Fatal("forgotten directory path mapping survived")
	}
	if len(watcher.forgot) != 1 || watcher.forgot[0] != "dir" {
		t.Fatalf("forgotten directory watches = %v, want [dir]", watcher.forgot)
	}
}
