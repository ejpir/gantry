//go:build linux || darwin || windows

package virtio

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gantry/internal/gutil"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// This file is the platform-neutral share-hub control layer: the export
// lifecycle (prepare, publish, swap, remove, revoke), the synthetic
// namespace root, and the virtio-fs device transport are defined exactly
// once here. The platforms contribute only the per-export backend
// (newExportNode) and its node/file wrappers:
//
//   - Linux/macOS: loopback over a pinned root FD (vsharehub.go)
//   - Windows:     native passthrough over a pinned root HANDLE
//     (vsharehub_windows.go)
//
// Every policy decision that must hold on all hosts — default-deny
// namespace root, per-export RO, revocation semantics, atomic replace —
// lives below, not in the platform files.

const (
	virtioFSDeviceID = 26
	virtioFSHiprioQ  = 0
	virtioFSRequestQ = 1
	fsMaxChainBytes  = 256 << 10
	// FSTagLen lives in share.go (needed on all platforms)
)

// ShareExportState is the lifecycle of one logical share beneath the hub.
type ShareExportState int32

const (
	ShareExportActive ShareExportState = iota
	ShareExportDraining
	ShareExportRevoked
	ShareExportGone
)

func (s ShareExportState) String() string {
	switch s {
	case ShareExportActive:
		return "active"
	case ShareExportDraining:
		return "draining"
	case ShareExportRevoked:
		return "revoked"
	default:
		return "gone"
	}
}

// ShareExport is one prepared/published child of a ShareHub.
type ShareExport struct {
	Tag  string
	Path string
	RO   bool

	state atomic.Int32
	// node is the platform backend's root node, presented at /<tag>.
	node  fs.InodeEmbedder
	inode *fs.Inode
	// release drops the platform backend's pinned host resources (root
	// FD or handle). It runs at most once, from finish.
	release   func()
	finishOne sync.Once
}

// State reports the export lifecycle for the control plane and dashboard.
func (e *ShareExport) State() ShareExportState {
	if e == nil {
		return ShareExportGone
	}
	return ShareExportState(e.state.Load())
}

func (e *ShareExport) setState(state ShareExportState) {
	if e != nil {
		e.state.Store(int32(state))
	}
}

func (e *ShareExport) usable() bool {
	state := e.State()
	return state == ShareExportActive || state == ShareExportDraining
}

func (e *ShareExport) mutable() syscall.Errno {
	if !e.usable() {
		return syscall.ESTALE
	}
	if e.RO {
		return syscall.EROFS
	}
	return 0
}

func (e *ShareExport) finish() {
	if e == nil {
		return
	}
	e.finishOne.Do(func() {
		e.setState(ShareExportGone)
		if e.release != nil {
			e.release()
		}
	})
}

// PreparedShare is a fully validated export that has not entered the live
// namespace. Splitting preparation from publication lets the sandbox manager
// persist sandbox.json before making an infallible map swap.
type PreparedShare struct {
	export *ShareExport
}

// ClosePrepared releases a prepared export that was never published.
func (p *PreparedShare) ClosePrepared() {
	if p != nil && p.export != nil {
		p.export.finish()
	}
}

// ShareHub is one permanent virtio-fs device whose synthetic root contains a
// dynamically managed set of independently confined exports. It is the
// hot-add alternative to attaching a new virtio-mmio device per share.
type ShareHub struct {
	core    *Core
	tag     string
	handler fuseRequestHandler
	root    *shareHubRoot
	verbose bool

	mu       sync.RWMutex
	exports  map[string]*ShareExport
	all      map[*ShareExport]struct{}
	closed   bool
	nextSalt atomic.Uint64
}

// NewShareHub constructs an empty dynamic namespace. Persistent sandboxes add
// their configured shares before vmm.Prepare and can add more while running.
func NewShareHub() (*ShareHub, error) {
	debug := gutil.EnvOr("GANTRY_DEBUG_FS", "MINIVM_DEBUG_FS") != ""
	h := &ShareHub{
		tag:     "gantry-shares",
		exports: map[string]*ShareExport{},
		all:     map[*ShareExport]struct{}{},
		verbose: debug,
	}
	h.root = &shareHubRoot{hub: h}
	zero := time.Duration(0)
	raw := fs.NewNodeFS(h.root, &fs.Options{
		MountOptions: fuse.MountOptions{
			Debug:                debug,
			FsName:               h.tag,
			Name:                 "virtiofs",
			MaxWrite:             128 << 10,
			IgnoreSecurityLabels: true,
		},
		EntryTimeout:    &zero,
		AttrTimeout:     &zero,
		NegativeTimeout: &zero,
	})
	h.handler = fuse.NewProtocolServer(raw, &fuse.MountOptions{
		Debug:                debug,
		FsName:               h.tag,
		Name:                 "virtiofs",
		MaxWrite:             128 << 10,
		IgnoreSecurityLabels: true,
	})
	return h, nil
}

func validHubShareTag(tag string) bool {
	if tag == "" || len([]byte(tag)) > FSTagLen {
		return false
	}
	for _, r := range tag {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// Prepare validates and pins a host directory without publishing it. The
// export is aborted by ClosePrepared when the control-plane transaction
// fails. The platform half (newExportNode) pins the root and builds the
// node wrapper; everything about the lifecycle is platform-neutral.
func (h *ShareHub) Prepare(tag, path string, ro bool) (*PreparedShare, string, error) {
	if !validHubShareTag(tag) {
		return nil, "", fmt.Errorf("invalid share tag %q", tag)
	}
	exp := &ShareExport{Tag: tag, RO: ro}
	exp.state.Store(int32(ShareExportActive))
	node, finalPath, release, err := h.newExportNode(exp, path, h.nextSalt.Add(1)<<32)
	if err != nil {
		return nil, "", err
	}
	exp.Path = finalPath
	exp.node = node
	exp.release = release
	return &PreparedShare{export: exp}, exp.Path, nil
}

// Publish atomically exposes a prepared export as /<tag> in the hub root.
func (h *ShareHub) Publish(p *PreparedShare) (*ShareExport, error) {
	if p == nil || p.export == nil {
		return nil, fmt.Errorf("nil prepared share")
	}
	exp := p.export
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, fmt.Errorf("share hub is closed")
	}
	if old := h.exports[exp.Tag]; old != nil && old.State() != ShareExportGone {
		h.mu.Unlock()
		return nil, fmt.Errorf("share tag %q already exists", exp.Tag)
	}
	child := h.root.NewPersistentInode(context.Background(), exp.node, fs.StableAttr{Mode: fuse.S_IFDIR})
	if !h.root.AddChild(exp.Tag, child, false) {
		h.mu.Unlock()
		return nil, fmt.Errorf("share tag %q already exists", exp.Tag)
	}
	exp.inode = child
	h.exports[exp.Tag] = exp
	h.all[exp] = struct{}{}
	h.mu.Unlock()
	h.root.NotifyEntry(exp.Tag)
	return exp, nil
}

// Swap atomically replaces the export under p's tag: the prepared export
// is installed and the old one revoked in a single critical section, so a
// replacement never exposes a window where the tag is missing and, on any
// earlier failure, the working export is still live. The revoked export's
// nodes and handles fail ESTALE from here on.
func (h *ShareHub) Swap(p *PreparedShare) (old, exp *ShareExport, err error) {
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
	old.setState(ShareExportRevoked)
	oldChild := h.root.GetChild(exp.Tag)
	child := h.root.NewPersistentInode(context.Background(), exp.node, fs.StableAttr{Mode: fuse.S_IFDIR})
	if !h.root.AddChild(exp.Tag, child, true) {
		h.mu.Unlock()
		return nil, nil, fmt.Errorf("share tag %q swap failed", exp.Tag)
	}
	if oldChild != nil {
		oldChild.ForgetPersistent()
	}
	exp.inode = child
	h.exports[exp.Tag] = exp
	h.all[exp] = struct{}{}
	h.mu.Unlock()
	h.root.NotifyEntry(exp.Tag)
	return old, exp, nil
}

// Export returns the active or draining export for tag.
func (h *ShareHub) Export(tag string) *ShareExport {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.exports[tag]
}

// Exports returns a deterministic snapshot of the live namespace.
func (h *ShareHub) Exports() []*ShareExport {
	h.mu.RLock()
	out := make([]*ShareExport, 0, len(h.exports))
	for _, exp := range h.exports {
		out = append(out, exp)
	}
	h.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out
}

// Remove hides tag from new lookups immediately. Graceful removal leaves
// existing nodes and handles usable until the kernel forgets them; force
// revokes subsequent host-backed operations with ESTALE.
func (h *ShareHub) Remove(tag string, force bool) (*ShareExport, error) {
	h.mu.Lock()
	exp := h.exports[tag]
	if exp == nil {
		h.mu.Unlock()
		return nil, fmt.Errorf("share tag %q not found", tag)
	}
	if force {
		exp.setState(ShareExportRevoked)
	} else if exp.State() == ShareExportActive {
		exp.setState(ShareExportDraining)
	}
	delete(h.exports, tag)
	child := h.root.GetChild(tag)
	if child != nil {
		h.root.RmChild(tag)
		child.ForgetPersistent()
	}
	h.mu.Unlock()
	h.root.NotifyEntry(tag)
	if child == nil {
		exp.finish()
	}
	return exp, nil
}

// Close revokes every export and releases pinned roots at VM shutdown.
func (h *ShareHub) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	exports := make([]*ShareExport, 0, len(h.all))
	for exp := range h.all {
		exports = append(exports, exp)
	}
	h.mu.Unlock()
	for _, exp := range exports {
		exp.setState(ShareExportRevoked)
		exp.finish()
	}
	return nil
}

func (h *ShareHub) Tag() string { return h.tag }

// shareHubRoot is the synthetic top-level directory, shared verbatim by all
// platforms. It is deliberately not a loopback node: no guest request can
// address a host path outside an export.
type shareHubRoot struct {
	fs.Inode
	hub *ShareHub
}

func (n *shareHubRoot) active(tag string) *ShareExport {
	n.hub.mu.RLock()
	exp := n.hub.exports[tag]
	n.hub.mu.RUnlock()
	if exp == nil || !exp.usable() {
		return nil
	}
	return exp
}

var _ fs.NodeLookuper = (*shareHubRoot)(nil)

func (n *shareHubRoot) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.active(name) == nil {
		out.SetEntryTimeout(0)
		return nil, syscall.ENOENT
	}
	child := n.GetChild(name)
	if child == nil {
		return nil, syscall.ENOENT
	}
	var attr fuse.AttrOut
	if ga, ok := child.Operations().(fs.NodeGetattrer); ok && ga.Getattr(ctx, nil, &attr) == 0 {
		out.Attr = attr.Attr
	} else {
		out.Mode = fuse.S_IFDIR | 0o755
	}
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
	return child, 0
}

var _ fs.NodeReaddirer = (*shareHubRoot)(nil)

func (n *shareHubRoot) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	exports := n.hub.Exports()
	entries := make([]fuse.DirEntry, 0, len(exports))
	for _, exp := range exports {
		if !exp.usable() {
			continue
		}
		entries = append(entries, fuse.DirEntry{Name: exp.Tag, Mode: fuse.S_IFDIR})
	}
	return fs.NewListDirStream(entries), 0
}

var _ fs.NodeGetattrer = (*shareHubRoot)(nil)

func (n *shareHubRoot) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = fuse.S_IFDIR | 0o755
	out.Nlink = 2
	out.SetTimeout(0)
	return 0
}

// The hub root is a namespace, not a writable host directory.
func (n *shareHubRoot) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EROFS
}
func (n *shareHubRoot) Mknod(ctx context.Context, name string, mode, dev uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EROFS
}
func (n *shareHubRoot) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	return nil, nil, 0, syscall.EROFS
}
func (n *shareHubRoot) Unlink(ctx context.Context, name string) syscall.Errno { return syscall.EROFS }
func (n *shareHubRoot) Rmdir(ctx context.Context, name string) syscall.Errno  { return syscall.EROFS }
func (n *shareHubRoot) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	return syscall.EXDEV
}
func (n *shareHubRoot) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EXDEV
}
func (n *shareHubRoot) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EROFS
}
func (n *shareHubRoot) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	return syscall.EROFS
}

// Device transport: two virtio queues and one logical request queue
// regardless of export count. Identical on every platform.
func (h *ShareHub) deviceID() uint32 { return virtioFSDeviceID }
func (h *ShareHub) features() uint64 { return 0 }
func (h *ShareHub) numQueues() int   { return 2 }
func (h *ShareHub) reset()           {}
func (h *ShareHub) setCore(c *Core)  { h.core = c }

func (h *ShareHub) configRead(off uint64, p []byte) {
	var cfg [FSTagLen + 4]byte
	copy(cfg[:FSTagLen], []byte(h.tag))
	binary.LittleEndian.PutUint32(cfg[FSTagLen:], 1)
	if off < uint64(len(cfg)) {
		copy(p, cfg[off:])
	}
}
func (h *ShareHub) configWrite(off uint64, p []byte) {}

func (h *ShareHub) logf(format string, args ...any) {
	if h.verbose {
		fmt.Printf("[fs %s] "+format+"\n", append([]any{h.tag}, args...)...)
	}
}

func (h *ShareHub) handleQueue(qn int) {
	if qn != virtioFSHiprioQ && qn != virtioFSRequestQ {
		return
	}
	q := &h.core.queues[qn]
	for {
		head, chain, ok := h.core.availChain(qn)
		if !ok {
			return
		}
		readable, writable := splitChain(chain)
		in, err := h.readIOV(readable)
		if err != nil {
			h.logf("read request descriptors: %v", err)
			h.core.pushUsed(q, head, 0)
			continue
		}
		out := make([][]byte, len(writable))
		for i, d := range writable {
			out[i] = make([]byte, d.len)
		}
		n, status := h.handler.HandleRequest(in, out)
		if status != fuse.OK {
			h.logf("protocol request failed: %v", status)
			n = h.writeProtocolError(in, out, status)
		}
		if len(writable) == 0 {
			n = 0
		}
		if n < 0 {
			n = 0
		}
		capacity := 0
		for _, b := range out {
			capacity += len(b)
		}
		if n > capacity {
			n = capacity
		}
		written, err := h.writeIOV(writable, out, n)
		if err != nil {
			h.logf("write response descriptors: %v", err)
			written = 0
		}
		h.core.pushUsed(q, head, written)
	}
}

func (h *ShareHub) readIOV(ds []desc) ([][]byte, error) {
	out := make([][]byte, len(ds))
	for i, d := range ds {
		out[i] = make([]byte, d.len)
		if err := h.core.mem.readAt(d.addr, out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (h *ShareHub) writeIOV(ds []desc, bufs [][]byte, limit int) (uint32, error) {
	var written uint32
	remaining := limit
	for i, d := range ds {
		if remaining <= 0 || i >= len(bufs) {
			break
		}
		b := bufs[i]
		if len(b) > remaining {
			b = b[:remaining]
		}
		if len(b) > int(d.len) {
			b = b[:d.len]
		}
		if err := h.core.mem.writeAt(d.addr, b); err != nil {
			return written, err
		}
		written += uint32(len(b))
		remaining -= len(b)
	}
	return written, nil
}

func (h *ShareHub) writeProtocolError(in, out [][]byte, status fuse.Status) int {
	if len(out) == 0 || len(out[0]) < 16 {
		return 0
	}
	buf := out[0][:16]
	binary.LittleEndian.PutUint32(buf[0:4], 16)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(-int32(status)))
	if len(in) > 0 && len(in[0]) >= 16 {
		copy(buf[8:16], in[0][8:16])
	}
	return 16
}

func (h *ShareHub) maxChainBytes(qn int) uint64 { return fsMaxChainBytes }
