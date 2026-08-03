//go:build windows

package virtio

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gantry/internal/gutil"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/windows"
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
	backend   *winExportFS
	node      *winShareNode
	inode     *fs.Inode
	finishOne sync.Once
}

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
		if e.backend != nil {
			_ = e.backend.Close()
		}
	})
}

type PreparedShare struct{ export *ShareExport }

// ShareHub is one permanent virtio-fs device whose synthetic root contains a
// dynamically managed set of independently confined Windows passthrough
// exports.
type ShareHub struct {
	core    *Core
	tag     string
	handler fuseRequestHandler
	root    *winShareHubRoot
	verbose bool

	mu       sync.RWMutex
	exports  map[string]*ShareExport
	all      map[*ShareExport]struct{}
	closed   bool
	nextSalt atomic.Uint64
}

const (
	virtioFSDeviceID = 26
	virtioFSHiprioQ  = 0
	virtioFSRequestQ = 1
	fsMaxChainBytes  = 256 << 10
)

type fuseRequestHandler interface {
	HandleRequest(in, out [][]byte) (int, fuse.Status)
}

// Linux open(2) flag values as they appear on the virtio-fs wire. They are
// intentionally not Windows os.O_* values.
const (
	linuxOAccmode   = 0x3
	linuxOCreat     = 0x40
	linuxOExcl      = 0x80
	linuxOTrunc     = 0x200
	linuxOAppend    = 0x400
	linuxODirectory = 0x10000
	linuxOTmpfile   = 0x410000

	openWriteFlags = linuxOAccmode | linuxOCreat | linuxOTrunc | linuxOAppend | linuxOTmpfile
)

func NewShareHub() (*ShareHub, error) {
	debug := gutil.EnvOr("GANTRY_DEBUG_FS", "MINIVM_DEBUG_FS") != ""
	h := &ShareHub{
		tag:     "gantry-shares",
		exports: map[string]*ShareExport{},
		all:     map[*ShareExport]struct{}{},
		verbose: debug,
	}
	h.root = &winShareHubRoot{hub: h}
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

func (h *ShareHub) Prepare(tag, sharePath string, ro bool) (*PreparedShare, string, error) {
	if !validHubShareTag(tag) {
		return nil, "", fmt.Errorf("invalid share tag %q", tag)
	}
	salt := h.nextSalt.Add(1) << 32
	backend, err := newWinExportFS(sharePath, salt)
	if err != nil {
		return nil, "", err
	}
	exp := &ShareExport{Tag: tag, Path: backend.path, RO: ro, backend: backend}
	exp.state.Store(int32(ShareExportActive))
	exp.node = &winShareNode{export: exp, backend: backend}
	return &PreparedShare{export: exp}, exp.Path, nil
}

func (p *PreparedShare) ClosePrepared() {
	if p != nil && p.export != nil {
		p.export.finish()
	}
}

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

func (h *ShareHub) Export(tag string) *ShareExport {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.exports[tag]
}

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

// winShareHubRoot is the synthetic namespace root. It has no host path.
type winShareHubRoot struct {
	fs.Inode
	hub *ShareHub
}

func (n *winShareHubRoot) active(tag string) *ShareExport {
	n.hub.mu.RLock()
	exp := n.hub.exports[tag]
	n.hub.mu.RUnlock()
	if exp == nil || !exp.usable() {
		return nil
	}
	return exp
}

var _ fs.NodeLookuper = (*winShareHubRoot)(nil)

func (n *winShareHubRoot) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
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

var _ fs.NodeReaddirer = (*winShareHubRoot)(nil)

func (n *winShareHubRoot) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	exports := n.hub.Exports()
	entries := make([]fuse.DirEntry, 0, len(exports))
	for _, exp := range exports {
		if exp.usable() {
			entries = append(entries, fuse.DirEntry{Name: exp.Tag, Mode: fuse.S_IFDIR})
		}
	}
	return fs.NewListDirStream(entries), 0
}

var _ fs.NodeGetattrer = (*winShareHubRoot)(nil)

func (n *winShareHubRoot) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = fuse.S_IFDIR | 0o755
	out.Nlink = 2
	out.SetTimeout(0)
	return 0
}

func (n *winShareHubRoot) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EROFS
}
func (n *winShareHubRoot) Mknod(ctx context.Context, name string, mode, dev uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EROFS
}
func (n *winShareHubRoot) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	return nil, nil, 0, syscall.EROFS
}
func (n *winShareHubRoot) Unlink(ctx context.Context, name string) syscall.Errno {
	return syscall.EROFS
}
func (n *winShareHubRoot) Rmdir(ctx context.Context, name string) syscall.Errno { return syscall.EROFS }
func (n *winShareHubRoot) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	return syscall.EXDEV
}
func (n *winShareHubRoot) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EXDEV
}
func (n *winShareHubRoot) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EROFS
}
func (n *winShareHubRoot) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	return syscall.EROFS
}

// winShareNode is one inode beneath a Windows passthrough export.
type winShareNode struct {
	fs.Inode
	export  *ShareExport
	backend *winExportFS
}

func (n *winShareNode) available() syscall.Errno {
	if n.export == nil || !n.export.usable() {
		return syscall.ESTALE
	}
	return 0
}

func (n *winShareNode) mutable() syscall.Errno {
	if n.export == nil {
		return syscall.ESTALE
	}
	return n.export.mutable()
}

func (n *winShareNode) relPath() string {
	if n.export == nil || n.export.node == nil || n.export.node == n {
		return ""
	}
	return n.Inode.Path(&n.export.node.Inode)
}

func (n *winShareNode) child() *winShareNode {
	return &winShareNode{export: n.export, backend: n.backend}
}

func (n *winShareNode) OnForget() {
	if n.export != nil && n.export.node == n {
		n.export.finish()
	}
}

var _ fs.NodeLookuper = (*winShareNode)(nil)

func (n *winShareNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.available(); errno != 0 {
		return nil, errno
	}
	info, errno := n.backend.lookup(n.relPath(), name)
	if errno != 0 {
		out.SetEntryTimeout(0)
		return nil, errno
	}
	out.Attr = info.attr
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
	mode := info.attr.Mode & 0o170000
	return n.NewInode(ctx, n.child(), fs.StableAttr{Ino: info.attr.Ino, Mode: mode}), 0
}

var _ fs.NodeGetattrer = (*winShareNode)(nil)

func (n *winShareNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if errno := n.available(); errno != 0 {
		return errno
	}
	if file, ok := f.(*winShareFile); ok && file.wf != nil {
		info, errno := n.backend.infoForHandle(windows.Handle(file.wf.file.Fd()))
		if errno == 0 {
			out.Attr = info.attr
			out.SetTimeout(0)
		}
		return errno
	}
	h, info, errno := n.backend.resolve(n.relPath(), winMetadataAccess,
		windows.FILE_OPEN, winBaseOpenOpts, false)
	if errno != 0 {
		return errno
	}
	_ = windows.CloseHandle(h)
	out.Attr = info.attr
	out.SetTimeout(0)
	return 0
}

var _ fs.NodeSetattrer = (*winShareNode)(nil)

func (n *winShareNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	var wf *winOpenFile
	if file, ok := f.(*winShareFile); ok {
		wf = file.wf
	}
	attr, errno := n.backend.setattr(n.relPath(), wf, in)
	if errno == 0 {
		out.Attr = attr
		out.SetTimeout(0)
	}
	return errno
}

var _ fs.NodeOpener = (*winShareNode)(nil)

func (n *winShareNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if errno := n.available(); errno != 0 {
		return nil, 0, errno
	}
	if n.export.RO && flags&openWriteFlags != 0 {
		return nil, 0, syscall.EROFS
	}
	wf, _, errno := n.backend.open(n.relPath(), flags)
	if errno != 0 {
		return nil, 0, errno
	}
	return &winShareFile{wf: wf, backend: n.backend, export: n.export}, fuse.FOPEN_DIRECT_IO, 0
}

var _ fs.NodeCreater = (*winShareNode)(nil)

func (n *winShareNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if errno := n.mutable(); errno != 0 {
		return nil, nil, 0, errno
	}
	wf, info, errno := n.backend.create(n.relPath(), name, flags, mode)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	out.Attr = info.attr
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
	child := n.NewInode(ctx, n.child(), fs.StableAttr{Ino: info.attr.Ino, Mode: fuse.S_IFREG})
	return child, &winShareFile{wf: wf, backend: n.backend, export: n.export}, fuse.FOPEN_DIRECT_IO, 0
}

var _ fs.NodeMkdirer = (*winShareNode)(nil)

func (n *winShareNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.mutable(); errno != 0 {
		return nil, errno
	}
	info, errno := n.backend.mkdir(n.relPath(), name)
	if errno != 0 {
		return nil, errno
	}
	out.Attr = info.attr
	out.SetEntryTimeout(0)
	out.SetAttrTimeout(0)
	return n.NewInode(ctx, n.child(), fs.StableAttr{Ino: info.attr.Ino, Mode: fuse.S_IFDIR}), 0
}

var _ fs.NodeUnlinker = (*winShareNode)(nil)

func (n *winShareNode) Unlink(ctx context.Context, name string) syscall.Errno {
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	return n.backend.delete(n.relPath(), name, false)
}

var _ fs.NodeRmdirer = (*winShareNode)(nil)

func (n *winShareNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	return n.backend.delete(n.relPath(), name, true)
}

var _ fs.NodeRenamer = (*winShareNode)(nil)

func (n *winShareNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	other, ok := newParent.(*winShareNode)
	if !ok || other.export != n.export {
		return syscall.EXDEV
	}
	if errno := other.mutable(); errno != 0 {
		return errno
	}
	return n.backend.rename(n.relPath(), name, other.relPath(), newName, flags)
}

func (n *winShareNode) Mknod(ctx context.Context, name string, mode, dev uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.ENOSYS
}
func (n *winShareNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.ENOSYS
}
func (n *winShareNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.ENOSYS
}
func (n *winShareNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	return nil, syscall.ENOSYS
}

func (n *winShareNode) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	if errno := n.available(); errno != 0 {
		return 0, errno
	}
	return 0, syscall.ENOSYS
}

func (n *winShareNode) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	return syscall.ENOSYS
}

func (n *winShareNode) Removexattr(ctx context.Context, attr string) syscall.Errno {
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	return syscall.ENOSYS
}

var _ fs.NodeReaddirer = (*winShareNode)(nil)

func (n *winShareNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	if errno := n.available(); errno != 0 {
		return nil, errno
	}
	entries, errno := n.backend.readdir(n.relPath())
	if errno != 0 {
		return nil, errno
	}
	return &winShareDirStream{entries: entries, export: n.export}, 0
}

var _ fs.NodeAccesser = (*winShareNode)(nil)

func (n *winShareNode) Access(ctx context.Context, mask uint32) syscall.Errno {
	if errno := n.available(); errno != 0 {
		return errno
	}
	if n.export.RO && mask&2 != 0 { // W_OK
		return syscall.EROFS
	}
	return 0
}

var _ fs.NodeStatfser = (*winShareNode)(nil)

func (n *winShareNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	if errno := n.available(); errno != 0 {
		return errno
	}
	return n.backend.statfs(out)
}

type winShareDirStream struct {
	entries []fuse.DirEntry
	idx     int
	export  *ShareExport
}

func (d *winShareDirStream) HasNext() bool {
	return d.export != nil && d.export.usable() && d.idx < len(d.entries)
}

func (d *winShareDirStream) Next() (fuse.DirEntry, syscall.Errno) {
	if !d.HasNext() {
		return fuse.DirEntry{}, syscall.ESTALE
	}
	e := d.entries[d.idx]
	d.idx++
	e.Off = uint64(d.idx)
	return e, 0
}

func (d *winShareDirStream) Close() {}

type winShareFile struct {
	wf      *winOpenFile
	backend *winExportFS
	export  *ShareExport
}

func (f *winShareFile) available() syscall.Errno {
	if f.export == nil || !f.export.usable() {
		return syscall.ESTALE
	}
	return 0
}

func (f *winShareFile) mutable() syscall.Errno {
	if f.export == nil {
		return syscall.ESTALE
	}
	return f.export.mutable()
}

var _ fs.FileReader = (*winShareFile)(nil)

func (f *winShareFile) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if errno := f.available(); errno != 0 {
		return nil, errno
	}
	n, err := f.wf.read(dest, off)
	if err != nil && err != io.EOF {
		return nil, ntStatusErrno(err)
	}
	return fuse.ReadResultData(dest[:n]), 0
}

var _ fs.FileWriter = (*winShareFile)(nil)

func (f *winShareFile) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	if errno := f.mutable(); errno != 0 {
		return 0, errno
	}
	n, err := f.wf.write(data, off)
	return uint32(n), ntStatusErrno(err)
}

var _ fs.FileGetattrer = (*winShareFile)(nil)

func (f *winShareFile) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	if errno := f.available(); errno != 0 {
		return errno
	}
	info, errno := f.backend.infoForHandle(windows.Handle(f.wf.file.Fd()))
	if errno == 0 {
		out.Attr = info.attr
		out.SetTimeout(0)
	}
	return errno
}

var _ fs.FileSetattrer = (*winShareFile)(nil)

func (f *winShareFile) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if errno := f.mutable(); errno != 0 {
		return errno
	}
	attr, errno := f.backend.setattr("", f.wf, in)
	if errno == 0 {
		out.Attr = attr
		out.SetTimeout(0)
	}
	return errno
}

var _ fs.FileFlusher = (*winShareFile)(nil)

func (f *winShareFile) Flush(ctx context.Context) syscall.Errno {
	if errno := f.available(); errno != 0 {
		return errno
	}
	if !f.wf.writable {
		// FlushFileBuffers requires write access; a flush after reads on a
		// read-only handle is a no-op, not an access-denied error.
		return 0
	}
	return ntStatusErrno(windows.FlushFileBuffers(windows.Handle(f.wf.file.Fd())))
}

var _ fs.FileFsyncer = (*winShareFile)(nil)

func (f *winShareFile) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	if errno := f.available(); errno != 0 {
		return errno
	}
	if !f.wf.writable {
		// same FlushFileBuffers access requirement as Flush
		return 0
	}
	return ntStatusErrno(windows.FlushFileBuffers(windows.Handle(f.wf.file.Fd())))
}

var _ fs.FileReleaser = (*winShareFile)(nil)

func (f *winShareFile) Release(ctx context.Context) syscall.Errno {
	return ntStatusErrno(f.wf.close())
}

var _ fs.FileLseeker = (*winShareFile)(nil)

func (f *winShareFile) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
	if errno := f.available(); errno != 0 {
		return 0, errno
	}
	n, err := f.wf.file.Seek(int64(off), int(whence))
	return uint64(n), ntStatusErrno(err)
}

// Device transport mirrors the Unix hub: two virtio queues and one logical
// request queue regardless of export count.
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
