//go:build linux || darwin || windows

// Package sharefs owns host filesystem capabilities, export policy, and the
// dynamic FUSE namespace used for sandbox directory sharing.
package sharefs

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ejpir/gantry/internal/fusewire"
	sharelifecycle "github.com/ejpir/gantry/internal/sharefs/lifecycle"
	"github.com/ejpir/gantry/internal/shares"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// This file is the platform-neutral share-hub manager. Export lifecycle is
// defined in export.go and the synthetic namespace in namespace.go. Platforms
// contribute only the per-export backend and its node/handle wrappers:
//
//   - Linux/macOS: loopback over a pinned root FD
//   - Windows: native passthrough over a pinned root HANDLE
//
// Cross-platform policy remains in these three neutral files, not in the
// platform backends.

// Hub is a synthetic FUSE root containing dynamically managed exports. It
// owns host filesystem capabilities but no virtio device or IPC transport.
type Hub struct {
	root       *shareHubRoot
	protocol   *fuse.ProtocolServer
	handler    fusewire.Handler
	guard      *requestGuard
	debugFS    bool
	request    sync.RWMutex // drains guest operations before root capabilities close
	lifecycle  sharelifecycle.Owner
	finalizers deferredFinalizers

	notificationsReady atomic.Bool

	// rootVer is the namespace mutation stamp, reported as the hub root's
	// mtime. The synthetic root remains uncached even when reverse
	// invalidations are available, so hot-add never depends on watcher health.
	rootVer atomic.Int64

	mu            sync.RWMutex
	exports       map[string]*Export
	all           map[*Export]struct{}
	policyBlocked bool      // request lock; fail-closed live-policy barrier
	deadline      time.Time // request lock; hard expiry of an optional host policy
	nextSalt      atomic.Uint64
}

// NewHub constructs an empty dynamic namespace. Persistent sandboxes add
// their configured shares before vmm.Prepare and can add more while running.
func NewHub() (*Hub, error) {
	debug := os.Getenv("GANTRY_DEBUG_FS") != ""
	zeroMessageOpenDir := runtime.GOOS != "windows"
	capabilities := uint64(fuse.CAP_READDIRPLUS_AUTO | fuse.CAP_GANTRY_READDIR_EOF)
	if zeroMessageOpenDir {
		capabilities |= fuse.CAP_NO_OPENDIR_SUPPORT
	}
	h := &Hub{
		exports: map[string]*Export{},
		all:     map[*Export]struct{}{},
		guard:   newRequestGuard(),
		debugFS: debug,
	}
	h.root = &shareHubRoot{hub: h}
	zero := time.Duration(0)
	raw := fs.NewNodeFS(h.root, &fs.Options{
		MountOptions: fuse.MountOptions{
			Debug:                debug,
			FsName:               shares.HubTag,
			Name:                 "virtiofs",
			MaxWrite:             128 << 10,
			ExtraCapabilities:    capabilities,
			IgnoreSecurityLabels: true,
			PanicHandler:         h.guard.containPanic,
		},
		EntryTimeout:       &zero,
		AttrTimeout:        &zero,
		NegativeTimeout:    &zero,
		ReadDirPlusLookup:  prefetchReadDirPlusEntry,
		ZeroMessageOpenDir: zeroMessageOpenDir,
	})
	h.protocol = fuse.NewProtocolServer(raw, &fuse.MountOptions{
		Debug:                debug,
		FsName:               shares.HubTag,
		Name:                 "virtiofs",
		MaxWrite:             128 << 10,
		ExtraCapabilities:    capabilities,
		IgnoreSecurityLabels: true,
		PanicHandler:         h.guard.containPanic,
	})
	h.handler = h.protocol
	h.guard.setReporter(h.handler)
	return h, nil
}

// Prepare validates and pins a host directory without publishing it. The
// export is aborted by ClosePrepared when the control-plane transaction
// fails. The platform half (newExportNode) pins the root and builds the
// node wrapper; everything about the lifecycle is platform-neutral.
func (h *Hub) Prepare(tag, path string, ro bool) (*Prepared, string, error) {
	return h.PrepareMapped(tag, path, ro, nil, nil)
}

// PrepareMapped is Prepare with optional guest-visible UID/GID mapping.
func (h *Hub) PrepareMapped(tag, path string, ro bool, uid, gid *uint32) (*Prepared, string, error) {
	if h == nil {
		return nil, "", fmt.Errorf("share hub is closed")
	}
	// Preparation acquires host capabilities. Join the serving read side so
	// Close cannot return while an admitted preparation is still acquiring
	// resources that it will transfer to Prepared.
	h.request.RLock()
	defer h.request.RUnlock()
	if h.lifecycle.Phase() != sharelifecycle.Active {
		return nil, "", fmt.Errorf("share hub is closed")
	}
	if err := shares.ValidateShareTag(tag); err != nil {
		return nil, "", err
	}
	if (uid != nil || gid != nil) && !shareOwnerMappingSupported {
		// Explicit beats silently divergent: the Windows passthrough
		// backend always reports the host's real ownership, so accepting
		// the option there would make it a no-op the user asked for.
		return nil, "", fmt.Errorf("share uid=/gid= ownership mapping is not supported on this platform")
	}
	exp := &Export{Tag: tag, RO: ro, UID: uid, GID: gid, hub: h, watchRootFD: -1}
	node, identity, release, err := newExportNode(exp, path, h.nextSalt.Add(1)<<32)
	if err != nil {
		return nil, "", err
	}
	if err := identity.ValidateExport(); err != nil {
		release()
		return nil, "", err
	}
	exp.identity = identity
	exp.Path = identity.Path()
	exp.node = node
	exp.release = release
	exp.coherence = newExportCoherence(exp)
	return &Prepared{export: exp}, exp.Path, nil
}

// Publish atomically exposes a prepared export as /<tag> in the hub root.
func (h *Hub) Publish(p *Prepared) (*Export, error) {
	exp, lease, ok := p.acquire()
	if !ok || exp == nil {
		return nil, fmt.Errorf("nil prepared share")
	}
	consumed := false
	defer func() { p.complete(lease, consumed) }()
	if exp.hub != h {
		return nil, fmt.Errorf("prepared share belongs to another hub")
	}
	// Publication may reuse a path whose gracefully removed export has just
	// reached OnForget. Drain old readers before a new independently locked
	// namespace can become reachable.
	h.request.Lock()
	defer h.request.Unlock()
	h.mu.Lock()
	if h.lifecycle.Phase() != sharelifecycle.Active {
		h.mu.Unlock()
		return nil, fmt.Errorf("share hub is closed")
	}
	if old := h.exports[exp.Tag]; old != nil && old.State() != ExportGone {
		h.mu.Unlock()
		return nil, fmt.Errorf("share tag %q already exists", exp.Tag)
	}
	child := h.root.NewPersistentInode(context.Background(), exp.node, fs.StableAttr{Mode: fuse.S_IFDIR})
	if !h.root.AddChild(exp.Tag, child, false) {
		h.mu.Unlock()
		return nil, fmt.Errorf("share tag %q already exists", exp.Tag)
	}
	exp.inode = child
	if exp.coherence != nil {
		exp.coherence.attachRoot(child)
	}
	exp.onFinish = h.unregister
	exp.finishDrain = h.scheduleFinish
	h.exports[exp.Tag] = exp
	h.all[exp] = struct{}{}
	consumed = true
	h.mu.Unlock()
	h.bumpRootVer()
	_ = h.root.NotifyEntry(exp.Tag)
	return exp, nil
}

// Swap atomically replaces the export under p's tag: the prepared export
// is installed and the old one revoked in a single critical section, so a
// replacement never exposes a window where the tag is missing and, on any
// earlier failure, the working export is still live. The revoked export's
// nodes and handles fail ESTALE from here on.
func (h *Hub) Swap(p *Prepared) (old, exp *Export, err error) {
	candidate, lease, ok := p.acquire()
	if !ok || candidate == nil {
		return nil, nil, fmt.Errorf("nil prepared share")
	}
	consumed := false
	defer func() { p.complete(lease, consumed) }()
	if candidate.hub != h {
		return nil, nil, fmt.Errorf("prepared share belongs to another hub")
	}
	// A replacement must not publish a second export over the same host tree
	// while an old request is between its policy check and host operation.
	// HandleRequest holds the read side for the whole FUSE request, so this
	// writer lock drains every in-flight operation before the namespace and
	// lifecycle state change together.
	h.request.Lock()
	defer h.request.Unlock()
	exp = candidate
	h.mu.Lock()
	if h.lifecycle.Phase() != sharelifecycle.Active {
		h.mu.Unlock()
		return nil, nil, fmt.Errorf("share hub is closed")
	}
	old = h.exports[exp.Tag]
	if old == nil {
		h.mu.Unlock()
		return nil, nil, fmt.Errorf("share tag %q not found", exp.Tag)
	}
	oldChild := h.root.GetChild(exp.Tag)
	child := h.root.NewPersistentInode(context.Background(), exp.node, fs.StableAttr{Mode: fuse.S_IFDIR})
	if !h.root.AddChild(exp.Tag, child, true) {
		h.mu.Unlock()
		return nil, nil, fmt.Errorf("share tag %q swap failed", exp.Tag)
	}
	old.advanceState(ExportRevoked)
	if old.coherence != nil {
		old.coherence.revoke()
	}
	exp.inode = child
	if exp.coherence != nil {
		exp.coherence.attachRoot(child)
	}
	exp.onFinish = h.unregister
	exp.finishDrain = h.scheduleFinish
	h.exports[exp.Tag] = exp
	h.all[exp] = struct{}{}
	consumed = true
	h.mu.Unlock()
	if oldChild != nil {
		oldChild.ForgetPersistent()
		// If ForgetPersistent synchronously delivered OnForget, this caller
		// already owns the writer gate and can preserve synchronous cleanup.
		if old.finishScheduled.Load() {
			old.finishNow()
		}
	}
	h.bumpRootVer()
	_ = h.root.NotifyEntry(exp.Tag)
	return old, exp, nil
}

// Export returns the active or draining export for tag.
func (h *Hub) Export(tag string) *Export {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.exports[tag]
}

// Exports returns a deterministic snapshot of the live namespace.
func (h *Hub) Exports() []*Export {
	h.mu.RLock()
	out := make([]*Export, 0, len(h.exports))
	for _, exp := range h.exports {
		out = append(out, exp)
	}
	h.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out
}

func (h *Hub) exportCount() int {
	h.mu.RLock()
	count := len(h.exports)
	h.mu.RUnlock()
	return count
}

func (h *Hub) unregister(export *Export) {
	h.mu.Lock()
	delete(h.all, export)
	h.mu.Unlock()
}

// Remove hides tag from new lookups immediately. Graceful removal leaves
// existing nodes and handles usable until the kernel forgets them; force
// revokes subsequent host-backed operations with ESTALE.
func (h *Hub) Remove(tag string, force bool) (*Export, error) {
	// See Swap: removal is a lifecycle boundary. In particular, force removal
	// may not revoke and release a root while a request still uses it.
	h.request.Lock()
	defer h.request.Unlock()
	if h.lifecycle.Phase() != sharelifecycle.Active {
		return nil, fmt.Errorf("share hub is closed")
	}
	h.mu.Lock()
	exp := h.exports[tag]
	if exp == nil {
		h.mu.Unlock()
		return nil, fmt.Errorf("share tag %q not found", tag)
	}
	if force {
		exp.advanceState(ExportRevoked)
		if exp.coherence != nil {
			exp.coherence.revoke()
		}
	} else if exp.State() == ExportActive {
		exp.advanceState(ExportDraining)
	}
	delete(h.exports, tag)
	child := h.root.GetChild(tag)
	if child != nil {
		h.root.RmChild(tag)
	}
	h.mu.Unlock()
	if child != nil {
		child.ForgetPersistent()
		if exp.finishScheduled.Load() {
			exp.finishNow()
		}
	}
	h.bumpRootVer()
	_ = h.root.NotifyEntry(tag)
	if child == nil {
		exp.finishNow()
	}
	return exp, nil
}

func (h *Hub) syncExports() syscall.Errno {
	h.mu.RLock()
	exports := make([]*Export, 0, len(h.all))
	for export := range h.all {
		if export.usable() {
			exports = append(exports, export)
		}
	}
	h.mu.RUnlock()
	for _, export := range exports {
		if errno := syncExport(export); errno != 0 {
			return errno
		}
	}
	return 0
}

// Close revokes every export and releases pinned roots at VM shutdown. The
// lifecycle owner makes concurrent calls join one shutdown. Borrowers stop at
// the request gate before watchers and pinned roots are released.
func (h *Hub) Close() error {
	if h == nil {
		return nil
	}
	leader, done := h.lifecycle.BeginClose()
	if !leader {
		<-done
		return nil
	}

	h.request.Lock()
	h.finalizers.stopAdmission()
	h.notificationsReady.Store(false)
	if h.protocol != nil {
		h.protocol.GantrySetNotificationSink(nil)
		h.protocol.GantryCloseResources()
	}
	h.mu.RLock()
	exports := make([]*Export, 0, len(h.all))
	for exp := range h.all {
		exports = append(exports, exp)
	}
	h.mu.RUnlock()
	for _, exp := range exports {
		exp.advanceState(ExportRevoked)
		exp.finishNow()
	}
	h.request.Unlock()

	// Queued OnForget workers may have been waiting for the writer gate. They
	// observe already-finished exports, exit, and are joined before Closed.
	h.finalizers.wait()
	h.lifecycle.FinishClose()
	return nil
}

// scheduleFinish is called from OnForget while HandleRequest holds the read
// side of request. A joined worker waits for the writer side; writer preference
// then prevents later requests from overtaking release.
func (h *Hub) scheduleFinish(finish func()) {
	h.finalizers.schedule(func() {
		h.request.Lock()
		defer h.request.Unlock()
		finish()
	})
}

// SetNotificationSink is called by a transport only after the guest has
// negotiated and populated Gantry's notification virtqueue. Descendant cache
// policy becomes long-lived at that point, provided each export's host watcher
// is also healthy.
func (h *Hub) SetNotificationSink(sink fusewire.NotificationSink) {
	if h == nil || h.protocol == nil {
		return
	}
	h.request.RLock()
	defer h.request.RUnlock()
	if h.lifecycle.Phase() != sharelifecycle.Active {
		return
	}
	if sink == nil {
		h.notificationsReady.Store(false)
		h.protocol.GantrySetNotificationSink(nil)
		return
	}
	h.protocol.GantrySetNotificationSink(func(message []byte) fuse.Status {
		return sink(message)
	})
	h.notificationsReady.Store(true)
}

// SetDeadline bounds the lifetime of every export, including already-open
// handles. Zero means no policy deadline.
func (h *Hub) SetDeadline(deadline time.Time) {
	h.request.Lock()
	defer h.request.Unlock()
	if h.lifecycle.Phase() != sharelifecycle.Active {
		return
	}
	h.deadline = deadline
}

// SetPolicyBlocked drains in-flight filesystem requests and makes every new
// request fail closed while a live organization-policy update is reconciled.
func (h *Hub) SetPolicyBlocked(blocked bool) {
	if h == nil {
		return
	}
	h.request.Lock()
	defer h.request.Unlock()
	if h.lifecycle.Phase() != sharelifecycle.Active {
		return
	}
	h.policyBlocked = blocked
}

// SetPolicyAccess atomically publishes the policy deadline and per-export
// denials. A denied export remains pinned and can be restored by a later
// generation, but every node and already-open handle returns ESTALE.
func (h *Hub) SetPolicyAccess(deadline time.Time, denied map[string]bool) {
	if h == nil {
		return
	}
	h.request.Lock()
	defer h.request.Unlock()
	if h.lifecycle.Phase() != sharelifecycle.Active {
		return
	}
	h.deadline = deadline
	h.mu.RLock()
	defer h.mu.RUnlock()
	for export := range h.all {
		export.policyDenied.Store(denied[export.Tag])
	}
}

// HandleRequest serves one raw FUSE request. Hub remains transport-neutral;
// callers may connect it directly to virtio or through sharebroker.
func (h *Hub) HandleRequest(in, out [][]byte) (int, fuse.Status) {
	h.request.RLock()
	defer h.request.RUnlock()
	if h.lifecycle.Phase() != sharelifecycle.Active {
		return 0, fuse.EIO
	}
	if h.policyBlocked {
		return 0, fuse.EACCES
	}
	if !h.deadline.IsZero() && !time.Now().Before(h.deadline) {
		return 0, fuse.EACCES
	}
	return h.guard.handle(h.handler, in, out)
}

var (
	_ fusewire.Handler            = (*Hub)(nil)
	_ fusewire.NotificationSource = (*Hub)(nil)
)
