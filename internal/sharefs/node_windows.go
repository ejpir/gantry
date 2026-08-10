//go:build windows

package sharefs

import (
	"context"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/windows"
)

// winShareNode is one inode beneath a Windows passthrough export.
type winShareNode struct {
	fs.Inode
	export  *Export
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
	return n.Path(&root.Inode)
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
	if f != nil {
		file, ok := f.(*winShareFile)
		if !ok || !file.belongsTo(n) {
			return syscall.EBADF
		}
		info, errno := n.backend.infoForHandle(windows.Handle(file.wf.file.Fd()))
		if errno == 0 {
			out.Attr = info.attr
			out.SetTimeout(0)
		}
		return errno
	}
	h, info, errno := n.backend.resolve(n.relPath(), winMetadataAccess,
		windows.FILE_OPEN, winBaseOpenOpts)
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
	if f != nil {
		file, ok := f.(*winShareFile)
		if !ok || !file.belongsTo(n) {
			return syscall.EBADF
		}
		if errno := file.mutable(); errno != 0 {
			return errno
		}
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
	return &winShareFile{wf: wf, backend: n.backend, export: n.export, node: n}, fuse.FOPEN_DIRECT_IO, 0
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
	childOps := n.child()
	child := n.NewInode(ctx, childOps, fs.StableAttr{Ino: info.attr.Ino, Mode: fuse.S_IFREG})
	return child, &winShareFile{wf: wf, backend: n.backend, export: n.export, node: childOps}, fuse.FOPEN_DIRECT_IO, 0
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

func (n *winShareNode) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
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
	return n.backend.readdir(n.relPath(), n.export)
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
