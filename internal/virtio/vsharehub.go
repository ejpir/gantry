//go:build linux || darwin

package virtio

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gantry/internal/gutil"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
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

	state     atomic.Int32
	rootFD    *os.File
	node      *shareNode
	inode     *fs.Inode
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
		if e.rootFD != nil {
			_ = e.rootFD.Close()
		}
	})
}

// PreparedShare is a fully validated export that has not entered the live
// namespace. Splitting preparation from publication lets the sandbox manager
// persist sandbox.json before making an infallible map swap.
type PreparedShare struct {
	export *ShareExport
}

// ShareHub is one permanent virtio-fs device whose synthetic root contains a
// dynamically managed set of independently confined loopback exports. It is
// the hot-add alternative to attaching a new virtio-mmio device per share.
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
// export is aborted by ClosePrepared when the control-plane transaction fails.
func (h *ShareHub) Prepare(tag, path string, ro bool) (*PreparedShare, string, error) {
	if !validHubShareTag(tag) {
		return nil, "", fmt.Errorf("invalid share tag %q", tag)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", fmt.Errorf("resolve share path: %w", err)
	}
	rootFD, err := os.Open(abs)
	if err != nil {
		return nil, "", fmt.Errorf("open share root: %w", err)
	}
	st, err := rootFD.Stat()
	if err != nil || !st.IsDir() {
		_ = rootFD.Close()
		if err == nil {
			err = fmt.Errorf("not a directory")
		}
		return nil, "", fmt.Errorf("share root %s: %w", abs, err)
	}
	rootNode, err := fs.NewLoopbackRootFD(abs, int(rootFD.Fd()))
	if err != nil {
		_ = rootFD.Close()
		return nil, "", fmt.Errorf("create loopback export: %w", err)
	}
	ln, ok := rootNode.(*fs.LoopbackNode)
	if !ok {
		_ = rootFD.Close()
		return nil, "", fmt.Errorf("unexpected loopback root %T", rootNode)
	}
	ln.RootData.InoSalt = h.nextSalt.Add(1) << 32
	exp := &ShareExport{Tag: tag, Path: ln.RootData.RootPrefix, RO: ro, rootFD: rootFD}
	exp.state.Store(int32(ShareExportActive))
	rootData := ln.RootData
	rootData.NewNode = func(rd *fs.LoopbackRoot, parent *fs.Inode, name string, st *syscall.Stat_t) fs.InodeEmbedder {
		return &shareNode{LoopbackNode: fs.LoopbackNode{RootData: rd}, export: exp}
	}
	exp.node = &shareNode{LoopbackNode: fs.LoopbackNode{RootData: rootData}, export: exp}
	rootData.RootNode = exp.node
	return &PreparedShare{export: exp}, exp.Path, nil
}

// ClosePrepared releases a prepared export that was never published.
func (p *PreparedShare) ClosePrepared() {
	if p != nil && p.export != nil {
		p.export.finish()
	}
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
	child := h.root.NewPersistentInode(context.Background(), exp.node, fs.StableAttr{Mode: syscall.S_IFDIR})
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

// shareHubRoot is the synthetic top-level directory. It is deliberately not a
// loopback node: no guest request can address a host path outside an export.
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
		out.Mode = syscall.S_IFDIR | 0o755
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
		entries = append(entries, fuse.DirEntry{Name: exp.Tag, Mode: syscall.S_IFDIR})
	}
	return fs.NewListDirStream(entries), 0
}

var _ fs.NodeGetattrer = (*shareHubRoot)(nil)

func (n *shareHubRoot) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = syscall.S_IFDIR | 0o755
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

// shareNode wraps every loopback node beneath one export. It carries the
// export's RO policy and revocation state with the inode, so mixed RO/RW
// children can live beneath one writable guest mount.
type shareNode struct {
	fs.LoopbackNode
	export *ShareExport
}

func (n *shareNode) available() syscall.Errno {
	if n.export == nil || !n.export.usable() {
		return syscall.ESTALE
	}
	return 0
}

func (n *shareNode) mutable() syscall.Errno {
	if n.export == nil {
		return syscall.ESTALE
	}
	return n.export.mutable()
}

func (n *shareNode) wrapFile(f fs.FileHandle, errno syscall.Errno) (fs.FileHandle, uint32, syscall.Errno) {
	if errno != 0 || f == nil {
		return nil, 0, errno
	}
	return &shareFile{FileHandle: f, export: n.export}, 0, 0
}

var _ fs.NodeWrapChilder = (*shareNode)(nil)

func (n *shareNode) WrapChild(ctx context.Context, ops fs.InodeEmbedder) fs.InodeEmbedder {
	switch child := ops.(type) {
	case *shareNode:
		child.export = n.export
		return child
	case *fs.LoopbackNode:
		return &shareNode{LoopbackNode: fs.LoopbackNode{RootData: child.RootData}, export: n.export}
	default:
		return ops
	}
}

func (n *shareNode) OnForget() {
	// Only the export root owns the pinned root directory. Descendants can
	// forget independently throughout normal operation.
	if n.export != nil && n.RootData.RootNode == n {
		n.export.finish()
	}
}

func (n *shareNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.available(); errno != 0 {
		return nil, errno
	}
	return n.LoopbackNode.Lookup(ctx, name, out)
}

func (n *shareNode) Mknod(ctx context.Context, name string, mode, rdev uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.mutable(); errno != 0 {
		return nil, errno
	}
	// Special-file creation (device nodes, fifos, sockets) executes with
	// the VMM's host credentials; a guest must never plant device nodes
	// on the host, even inside a writable export. Regular files are
	// created through Create and are unaffected.
	return nil, syscall.EPERM
}

func (n *shareNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.mutable(); errno != 0 {
		return nil, errno
	}
	return n.LoopbackNode.Mkdir(ctx, name, mode, out)
}

func (n *shareNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	return n.LoopbackNode.Rmdir(ctx, name)
}

func (n *shareNode) Unlink(ctx context.Context, name string) syscall.Errno {
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	return n.LoopbackNode.Unlink(ctx, name)
}

func (n *shareNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	if other, ok := newParent.(*shareNode); ok {
		if errno := other.mutable(); errno != 0 {
			return errno
		}
		if other.export != n.export {
			return syscall.EXDEV
		}
	}
	return n.LoopbackNode.Rename(ctx, name, newParent, newName, flags)
}

func (n *shareNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	if errno := n.mutable(); errno != 0 {
		return nil, nil, 0, errno
	}
	inode, fh, fuseFlags, errno = n.LoopbackNode.Create(ctx, name, flags, mode, out)
	fh, _, errno = n.wrapFile(fh, errno)
	return inode, fh, fuseFlags, errno
}

func (n *shareNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.mutable(); errno != 0 {
		return nil, errno
	}
	return n.LoopbackNode.Symlink(ctx, target, name, out)
}

func (n *shareNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.mutable(); errno != 0 {
		return nil, errno
	}
	if other, ok := target.(*shareNode); ok && other.export != n.export {
		return nil, syscall.EXDEV
	}
	return n.LoopbackNode.Link(ctx, target, name, out)
}

func (n *shareNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	if errno := n.available(); errno != 0 {
		return nil, errno
	}
	return n.LoopbackNode.Readlink(ctx)
}

func (n *shareNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if errno := n.available(); errno != 0 {
		return nil, 0, errno
	}
	if n.export.RO && flags&openWriteFlags != 0 {
		return nil, 0, syscall.EROFS
	}
	fh, fuseFlags, errno := n.LoopbackNode.Open(ctx, flags)
	wrapped, _, errno := n.wrapFile(fh, errno)
	return wrapped, fuseFlags, errno
}

func (n *shareNode) OpendirHandle(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if errno := n.available(); errno != 0 {
		return nil, 0, errno
	}
	fh, fuseFlags, errno := n.LoopbackNode.OpendirHandle(ctx, flags)
	if errno != 0 || fh == nil {
		return nil, 0, errno
	}
	return &shareDirHandle{FileHandle: fh, export: n.export}, fuseFlags, 0
}

func (n *shareNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	if errno := n.available(); errno != 0 {
		return nil, errno
	}
	ds, errno := n.LoopbackNode.Readdir(ctx)
	if errno != 0 || ds == nil {
		return nil, errno
	}
	return &shareDirStream{DirStream: ds, export: n.export}, 0
}

func (n *shareNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if errno := n.available(); errno != 0 {
		return errno
	}
	return n.LoopbackNode.Getattr(ctx, f, out)
}

func (n *shareNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	errno := n.LoopbackNode.Setattr(ctx, f, in, out)
	// Ownership squash, as in NewFS: gVisor's gofer chowns every file it
	// creates, and non-root hosts cannot chown. Ownership is cosmetic on a
	// host share; apply all other requested attribute changes.
	if errno != syscall.EPERM && errno != syscall.EACCES {
		return errno
	}
	if in.Valid&(fuse.FATTR_UID|fuse.FATTR_GID) == 0 {
		return errno
	}
	retry := *in
	retry.Valid &^= fuse.FATTR_UID | fuse.FATTR_GID
	if retry.Valid != 0 {
		return n.LoopbackNode.Setattr(ctx, f, &retry, out)
	}
	return n.LoopbackNode.Getattr(ctx, f, out)
}

// xattrWriteAllowed permits only user.* attributes. security.*
// (capabilities, LSM labels), trusted.* and system.* (ACLs) are written
// with the VMM's host credentials and must never cross the guest boundary.
func xattrWriteAllowed(attr string) bool {
	return strings.HasPrefix(attr, "user.")
}

func (n *shareNode) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	if errno := n.available(); errno != 0 {
		return 0, errno
	}
	return n.LoopbackNode.Getxattr(ctx, attr, dest)
}

func (n *shareNode) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	if !xattrWriteAllowed(attr) {
		return syscall.EPERM
	}
	return n.LoopbackNode.Setxattr(ctx, attr, data, flags)
}

func (n *shareNode) Removexattr(ctx context.Context, attr string) syscall.Errno {
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	if !xattrWriteAllowed(attr) {
		return syscall.EPERM
	}
	return n.LoopbackNode.Removexattr(ctx, attr)
}

func (n *shareNode) Access(ctx context.Context, mask uint32) syscall.Errno {
	if errno := n.available(); errno != 0 {
		return errno
	}
	if n.export != nil && n.export.RO && mask&2 != 0 { // W_OK
		return syscall.EROFS
	}
	return 0
}

func (n *shareNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	if errno := n.available(); errno != 0 {
		return errno
	}
	return n.LoopbackNode.Statfs(ctx, out)
}

func (n *shareNode) CopyFileRange(ctx context.Context, fhIn fs.FileHandle, offIn uint64, out *fs.Inode, fhOut fs.FileHandle, offOut uint64, length uint64, flags uint64) (uint32, syscall.Errno) {
	if errno := n.available(); errno != 0 {
		return 0, errno
	}
	if outNode, ok := out.Operations().(*shareNode); ok {
		if errno := outNode.mutable(); errno != 0 {
			return 0, errno
		}
	} else {
		return 0, syscall.EXDEV
	}
	if wrapped, ok := fhIn.(*shareFile); ok {
		fhIn = wrapped.FileHandle
	}
	if wrapped, ok := fhOut.(*shareFile); ok {
		if errno := wrapped.mutable(); errno != 0 {
			return 0, errno
		}
		fhOut = wrapped.FileHandle
	}
	return n.LoopbackNode.CopyFileRange(ctx, fhIn, offIn, out, fhOut, offOut, length, flags)
}

// shareFile gates handle operations after a forced revoke. It deliberately
// does not expose PassthroughFd: kernel-side passthrough would bypass this
// security gate.
type shareFile struct {
	fs.FileHandle
	export *ShareExport
}

func (f *shareFile) available() syscall.Errno {
	if f.export == nil || !f.export.usable() {
		return syscall.ESTALE
	}
	return 0
}

func (f *shareFile) mutable() syscall.Errno {
	if f.export == nil {
		return syscall.ESTALE
	}
	return f.export.mutable()
}

func (f *shareFile) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if errno := f.available(); errno != 0 {
		return nil, errno
	}
	r, ok := f.FileHandle.(fs.FileReader)
	if !ok {
		return nil, syscall.ENOTSUP
	}
	return r.Read(ctx, dest, off)
}

func (f *shareFile) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	if errno := f.mutable(); errno != 0 {
		return 0, errno
	}
	w, ok := f.FileHandle.(fs.FileWriter)
	if !ok {
		return 0, syscall.ENOTSUP
	}
	return w.Write(ctx, data, off)
}

func (f *shareFile) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	if errno := f.available(); errno != 0 {
		return errno
	}
	g, ok := f.FileHandle.(fs.FileGetattrer)
	if !ok {
		return syscall.ENOTSUP
	}
	return g.Getattr(ctx, out)
}

func (f *shareFile) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if errno := f.mutable(); errno != 0 {
		return errno
	}
	s, ok := f.FileHandle.(fs.FileSetattrer)
	if !ok {
		return syscall.ENOTSUP
	}
	return s.Setattr(ctx, in, out)
}

func (f *shareFile) Flush(ctx context.Context) syscall.Errno {
	if fl, ok := f.FileHandle.(fs.FileFlusher); ok {
		return fl.Flush(ctx)
	}
	return 0
}

func (f *shareFile) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	if errno := f.available(); errno != 0 {
		return errno
	}
	if fsync, ok := f.FileHandle.(fs.FileFsyncer); ok {
		return fsync.Fsync(ctx, flags)
	}
	return 0
}

func (f *shareFile) Release(ctx context.Context) syscall.Errno {
	if rel, ok := f.FileHandle.(fs.FileReleaser); ok {
		return rel.Release(ctx)
	}
	return 0
}

func (f *shareFile) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
	if errno := f.available(); errno != 0 {
		return 0, errno
	}
	l, ok := f.FileHandle.(fs.FileLseeker)
	if !ok {
		return 0, syscall.ENOTSUP
	}
	return l.Lseek(ctx, off, whence)
}

func (f *shareFile) Allocate(ctx context.Context, off uint64, size uint64, mode uint32) syscall.Errno {
	if errno := f.mutable(); errno != 0 {
		return errno
	}
	a, ok := f.FileHandle.(fs.FileAllocater)
	if !ok {
		return syscall.ENOTSUP
	}
	return a.Allocate(ctx, off, size, mode)
}

func (f *shareFile) Ioctl(ctx context.Context, cmd uint32, arg uint64, input []byte, output []byte) (int32, syscall.Errno) {
	if errno := f.available(); errno != 0 {
		return 0, errno
	}
	// Default-deny: ioctls execute host-side with the VMM's credentials,
	// and several (FS_IOC_SETFLAGS, FS_IOC_FSSETXATTR, ...) mutate the
	// file even through an O_RDONLY descriptor, bypassing the export's RO
	// enforcement. Nothing a legitimate guest needs crosses this boundary.
	return 0, syscall.ENOTSUP
}

func (f *shareFile) Getlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	if errno := f.available(); errno != 0 {
		return errno
	}
	g, ok := f.FileHandle.(fs.FileGetlker)
	if !ok {
		return syscall.ENOTSUP
	}
	return g.Getlk(ctx, owner, lk, flags, out)
}

func (f *shareFile) Setlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	if errno := f.available(); errno != 0 {
		return errno
	}
	s, ok := f.FileHandle.(fs.FileSetlker)
	if !ok {
		return syscall.ENOTSUP
	}
	return s.Setlk(ctx, owner, lk, flags)
}

func (f *shareFile) Setlkw(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	if errno := f.available(); errno != 0 {
		return errno
	}
	s, ok := f.FileHandle.(fs.FileSetlkwer)
	if !ok {
		return syscall.ENOTSUP
	}
	return s.Setlkw(ctx, owner, lk, flags)
}

func (f *shareFile) Statx(ctx context.Context, flags uint32, mask uint32, out *fuse.StatxOut) syscall.Errno {
	if errno := f.available(); errno != 0 {
		return errno
	}
	s, ok := f.FileHandle.(fs.FileStatxer)
	if !ok {
		return syscall.ENOTSUP
	}
	return s.Statx(ctx, flags, mask, out)
}

// shareDirStream covers Readdir; shareDirHandle covers the OpendirHandle path.
type shareDirStream struct {
	fs.DirStream
	export *ShareExport
}

func (d *shareDirStream) HasNext() bool {
	if d.export == nil || !d.export.usable() {
		return false
	}
	return d.DirStream.HasNext()
}

func (d *shareDirStream) Next() (fuse.DirEntry, syscall.Errno) {
	if d.export == nil || !d.export.usable() {
		return fuse.DirEntry{}, syscall.ESTALE
	}
	return d.DirStream.Next()
}

type shareDirHandle struct {
	fs.FileHandle
	export *ShareExport
}

func (d *shareDirHandle) available() bool {
	return d.export != nil && d.export.usable()
}

func (d *shareDirHandle) Readdirent(ctx context.Context) (*fuse.DirEntry, syscall.Errno) {
	if !d.available() {
		return nil, syscall.ESTALE
	}
	r, ok := d.FileHandle.(fs.FileReaddirenter)
	if !ok {
		return nil, syscall.ENOTSUP
	}
	return r.Readdirent(ctx)
}

func (d *shareDirHandle) Seekdir(ctx context.Context, off uint64) syscall.Errno {
	if !d.available() {
		return syscall.ESTALE
	}
	s, ok := d.FileHandle.(fs.FileSeekdirer)
	if !ok {
		return syscall.ENOTSUP
	}
	return s.Seekdir(ctx, off)
}

func (d *shareDirHandle) Fsyncdir(ctx context.Context, flags uint32) syscall.Errno {
	if !d.available() {
		return syscall.ESTALE
	}
	f, ok := d.FileHandle.(fs.FileFsyncdirer)
	if !ok {
		return 0
	}
	return f.Fsyncdir(ctx, flags)
}

func (d *shareDirHandle) Releasedir(ctx context.Context, flags uint32) {
	if r, ok := d.FileHandle.(fs.FileReleasedirer); ok {
		r.Releasedir(ctx, flags)
	}
}

func (d *shareDirHandle) Ioctl(ctx context.Context, cmd uint32, arg uint64, input []byte, output []byte) (int32, syscall.Errno) {
	if !d.available() {
		return 0, syscall.ESTALE
	}
	// Default-deny like shareFile.Ioctl: no directory ioctl may execute
	// host-side with the VMM's credentials.
	return 0, syscall.ENOTSUP
}

// Device transport. This intentionally mirrors FS: virtio-fs has two queues
// and one request-queue count in config space regardless of the number of
// logical exports behind the hub.
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

// Tag reports the fixed virtio-fs transport tag.
func (h *ShareHub) Tag() string { return h.tag }
