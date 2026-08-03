//go:build windows

package virtio

import (
	"context"
	"io"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/windows"
)

// This file is the Windows half of the share hub: the native passthrough
// backend over a pinned root HANDLE and its node/file policy wrappers.
// The export lifecycle, synthetic namespace root, and device transport
// are platform-neutral and live in vsharehub_common.go.

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

// newExportNode pins sharePath beneath a root handle and builds the
// passthrough node presented as /<tag>. The returned release func drops
// the backend when the export finishes.
func (h *ShareHub) newExportNode(exp *ShareExport, sharePath string, salt uint64) (fs.InodeEmbedder, string, func(), error) {
	backend, err := newWinExportFS(sharePath, salt)
	if err != nil {
		return nil, "", nil, err
	}
	node := &winShareNode{export: exp, backend: backend}
	release := func() { _ = backend.Close() }
	return node, backend.path, release, nil
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
	if n.export == nil {
		return ""
	}
	root, _ := n.export.node.(*winShareNode)
	if root == nil || root == n {
		return ""
	}
	return n.Inode.Path(&root.Inode)
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
