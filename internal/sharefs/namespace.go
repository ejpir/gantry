//go:build linux || darwin || windows

package sharefs

import (
	"context"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// shareHubRoot is the synthetic top-level directory, shared verbatim by all
// platforms. It is deliberately not a loopback node: no guest request can
// address a host path outside an export.
type shareHubRoot struct {
	fs.Inode
	hub *Hub
}

func (n *shareHubRoot) active(tag string) *Export {
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
	out.Nlink = uint32(2 + n.hub.exportCount())
	ver := n.hub.rootVer.Load()
	out.Mtime = uint64(ver / int64(time.Second))
	out.Mtimensec = uint32(ver % int64(time.Second))
	out.Ctime, out.Ctimensec = out.Mtime, out.Mtimensec
	out.SetTimeout(0)
	return 0
}

// bumpRootVer stamps a namespace mutation so the next guest GETATTR of
// the mount root sees a new mtime and drops its cached listing.
func (h *Hub) bumpRootVer() { h.rootVer.Store(time.Now().UnixNano()) }

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
