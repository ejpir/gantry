//go:build linux || darwin || windows

// Package sharefs owns host filesystem capabilities, export policy, and the
// dynamic FUSE namespace used for sandbox directory sharing.
package sharefs

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ejpir/gantry/internal/fusewire"
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
	root    *shareHubRoot
	handler fusewire.Handler
	guard   *requestGuard
	request sync.RWMutex // drains guest operations before root capabilities close

	// rootVer is the namespace mutation stamp, reported as the hub
	// root's mtime. The guest kernel invalidates its cached READDIR of
	// the mount root only when the directory mtime changes — a static
	// mtime made hot-added tags invisible until remount (FUSE
	// NotifyEntry is a no-op over virtio-fs: no notify virtqueue).
	rootVer atomic.Int64

	mu       sync.RWMutex
	exports  map[string]*Export
	all      map[*Export]struct{}
	closed   bool
	nextSalt atomic.Uint64
}

// NewHub constructs an empty dynamic namespace. Persistent sandboxes add
// their configured shares before vmm.Prepare and can add more while running.
func NewHub() (*Hub, error) {
	debug := os.Getenv("GANTRY_DEBUG_FS") != ""
	h := &Hub{
		exports: map[string]*Export{},
		all:     map[*Export]struct{}{},
		guard:   newRequestGuard(),
	}
	h.root = &shareHubRoot{hub: h}
	zero := time.Duration(0)
	raw := fs.NewNodeFS(h.root, &fs.Options{
		MountOptions: fuse.MountOptions{
			Debug:                debug,
			FsName:               shares.HubTag,
			Name:                 "virtiofs",
			MaxWrite:             128 << 10,
			IgnoreSecurityLabels: true,
			PanicHandler:         h.guard.containPanic,
		},
		EntryTimeout:    &zero,
		AttrTimeout:     &zero,
		NegativeTimeout: &zero,
	})
	h.handler = fuse.NewProtocolServer(raw, &fuse.MountOptions{
		Debug:                debug,
		FsName:               shares.HubTag,
		Name:                 "virtiofs",
		MaxWrite:             128 << 10,
		IgnoreSecurityLabels: true,
		PanicHandler:         h.guard.containPanic,
	})
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
	if err := shares.ValidateShareTag(tag); err != nil {
		return nil, "", err
	}
	if (uid != nil || gid != nil) && !shareOwnerMappingSupported {
		// Explicit beats silently divergent: the Windows passthrough
		// backend always reports the host's real ownership, so accepting
		// the option there would make it a no-op the user asked for.
		return nil, "", fmt.Errorf("share uid=/gid= ownership mapping is not supported on this platform")
	}
	exp := &Export{Tag: tag, RO: ro, UID: uid, GID: gid}
	exp.state.Store(int32(ExportActive))
	node, identity, release, err := newExportNode(exp, path, h.nextSalt.Add(1)<<32)
	if err != nil {
		return nil, "", err
	}
	exp.identity = identity
	exp.Path = identity.Path()
	exp.node = node
	exp.release = release
	return &Prepared{export: exp}, exp.Path, nil
}

// Publish atomically exposes a prepared export as /<tag> in the hub root.
func (h *Hub) Publish(p *Prepared) (*Export, error) {
	if p == nil || p.export == nil {
		return nil, fmt.Errorf("nil prepared share")
	}
	exp := p.export
	h.mu.Lock()
	if h.closed {
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
	exp.onFinish = h.unregister
	h.exports[exp.Tag] = exp
	h.all[exp] = struct{}{}
	p.export = nil
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
	if p == nil || p.export == nil {
		return nil, nil, fmt.Errorf("nil prepared share")
	}
	exp = p.export
	h.mu.Lock()
	if h.closed {
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
	exp.inode = child
	exp.onFinish = h.unregister
	h.exports[exp.Tag] = exp
	h.all[exp] = struct{}{}
	p.export = nil
	h.mu.Unlock()
	if oldChild != nil {
		oldChild.ForgetPersistent()
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
	h.mu.Lock()
	exp := h.exports[tag]
	if exp == nil {
		h.mu.Unlock()
		return nil, fmt.Errorf("share tag %q not found", tag)
	}
	if force {
		exp.advanceState(ExportRevoked)
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
	}
	h.bumpRootVer()
	_ = h.root.NotifyEntry(tag)
	if child == nil {
		exp.finish()
	}
	return exp, nil
}

// Close revokes every export and releases pinned roots at VM shutdown.
func (h *Hub) Close() error {
	h.request.Lock()
	defer h.request.Unlock()
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	exports := make([]*Export, 0, len(h.all))
	for exp := range h.all {
		exports = append(exports, exp)
	}
	h.mu.Unlock()
	for _, exp := range exports {
		exp.advanceState(ExportRevoked)
		exp.finish()
	}
	return nil
}

// HandleRequest serves one raw FUSE request. Hub remains transport-neutral;
// callers may connect it directly to virtio or through sharebroker.
func (h *Hub) HandleRequest(in, out [][]byte) (int, fuse.Status) {
	h.request.RLock()
	defer h.request.RUnlock()
	if h.closed {
		return 0, fuse.EIO
	}
	return h.guard.handle(h.handler, in, out)
}

var _ fusewire.Handler = (*Hub)(nil)
