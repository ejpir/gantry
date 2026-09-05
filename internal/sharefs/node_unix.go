//go:build linux || darwin

package sharefs

import (
	"context"
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// shareNode wraps every loopback node beneath one export. It carries the
// export's RO policy and revocation state with the inode, so mixed RO/RW
// children can live beneath one writable guest mount.
type shareNode struct {
	fs.LoopbackNode
	export *Export
}

// GantryLockRawBridge is consumed by Gantry's go-fuse bridge around both a
// namespace backend call and its subsequent inode-tree update. Keeping this
// lock outside the Node method closes the otherwise unavoidable gap between
// those two phases.
func (n *shareNode) GantryLockRawBridge() {
	if n.export != nil {
		n.export.namespace.Lock()
	}
}

func (n *shareNode) GantryUnlockRawBridge() {
	if n.export != nil {
		n.export.namespace.Unlock()
	}
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

var _ fs.NodeSyncfser = (*shareNode)(nil)

func (n *shareNode) Syncfs(context.Context) syscall.Errno {
	return syncExport(n.export)
}

func (n *shareNode) isExportRoot() bool {
	return n.RootData != nil && n.RootData.RootNode == n
}

func (n *shareNode) wrapFile(f fs.FileHandle, errno syscall.Errno) (fs.FileHandle, uint32, syscall.Errno) {
	if errno != 0 || f == nil {
		return nil, 0, errno
	}
	return &shareFile{FileHandle: f, export: n.export}, 0, 0
}

// Linux O_NONBLOCK is carried on the FUSE wire even when the host is Darwin.
// Force it for the host open so a raced FIFO can never park a request worker;
// validate the actual descriptor, then restore the guest's requested mode.
const guestONonblock = uint32(0x800)

func releaseOpenedFile(ctx context.Context, file fs.FileHandle) {
	if releaser, ok := file.(fs.FileReleaser); ok {
		_ = releaser.Release(ctx)
	}
}

func validateOpenedFile(ctx context.Context, file fs.FileHandle, flags uint32) syscall.Errno {
	passthrough, ok := file.(fs.FilePassthroughFder)
	if !ok {
		releaseOpenedFile(ctx, file)
		return syscall.EPERM
	}
	fd, ok := passthrough.PassthroughFd()
	if !ok {
		releaseOpenedFile(ctx, file)
		return syscall.EBADF
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		releaseOpenedFile(ctx, file)
		return fs.ToErrno(err)
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFREG, syscall.S_IFDIR:
	default:
		releaseOpenedFile(ctx, file)
		return syscall.EPERM
	}
	if flags&guestONonblock == 0 {
		if err := syscall.SetNonblock(fd, false); err != nil {
			releaseOpenedFile(ctx, file)
			return fs.ToErrno(err)
		}
	}
	return 0
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
	if n.export != nil {
		shareDirectoryCache(n.export).forget(n.StableAttr().Ino)
	}
	if n.export != nil && n.export.coherence != nil {
		n.export.coherence.forget(n.EmbeddedInode())
	}
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
	inode, errno := n.LoopbackNode.Lookup(ctx, name, out)
	if errno == 0 {
		mapGuestOwner(n.export, &out.Attr)
		if n.export.coherence != nil {
			n.export.coherence.remember(n.EmbeddedInode(), name, inode)
		}
		cacheEntry(n.export, out)
	}
	return inode, errno
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
	if n.export == nil {
		return nil, syscall.ESTALE
	}
	if errno := n.mutable(); errno != 0 {
		return nil, errno
	}
	inode, errno := n.LoopbackNode.Mkdir(ctx, name, mode, out)
	if errno == 0 {
		mapGuestOwner(n.export, &out.Attr)
		if n.export.coherence != nil {
			n.export.coherence.remember(n.EmbeddedInode(), name, inode)
		}
		cacheEntry(n.export, out)
	}
	return inode, errno
}

func (n *shareNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	if n.export == nil {
		return syscall.ESTALE
	}
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	errno := n.LoopbackNode.Rmdir(ctx, name)
	if errno == 0 && n.export.coherence != nil {
		n.export.coherence.forgetPath(n.EmbeddedInode(), name)
	}
	return errno
}

func (n *shareNode) Unlink(ctx context.Context, name string) syscall.Errno {
	if n.export == nil {
		return syscall.ESTALE
	}
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	errno := n.LoopbackNode.Unlink(ctx, name)
	if errno == 0 && n.export.coherence != nil {
		n.export.coherence.forgetPath(n.EmbeddedInode(), name)
	}
	return errno
}

func (n *shareNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if errno := validateGuestRenameFlags(flags); errno != 0 {
		return errno
	}
	other, ok := newParent.(*shareNode)
	if !ok {
		return syscall.EXDEV
	}
	if n.export == nil || other.export != n.export {
		return syscall.EXDEV
	}
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	if errno := other.mutable(); errno != 0 {
		return errno
	}
	errno := n.LoopbackNode.Rename(ctx, name, newParent, newName, flags)
	if errno == 0 && n.export.coherence != nil {
		n.export.coherence.renamePath(n.EmbeddedInode(), name, other.EmbeddedInode(), newName)
	}
	return errno
}

func (n *shareNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	if n.export == nil {
		return nil, nil, 0, syscall.ESTALE
	}
	if errno := n.mutable(); errno != 0 {
		return nil, nil, 0, errno
	}
	if existing, statErr := n.HostChildStat(name); statErr == 0 {
		if existing.Mode&syscall.S_IFMT != syscall.S_IFREG {
			return nil, nil, 0, syscall.EPERM
		}
	} else if statErr != syscall.ENOENT {
		return nil, nil, 0, statErr
	}
	inode, fh, fuseFlags, errno = n.LoopbackNode.Create(ctx, name, flags|guestONonblock, mode, out)
	if errno == 0 {
		if errno = validateOpenedFile(ctx, fh, flags); errno != 0 {
			return nil, nil, 0, errno
		}
	}
	if errno == 0 {
		mapGuestOwner(n.export, &out.Attr)
		if n.export.coherence != nil {
			n.export.coherence.remember(n.EmbeddedInode(), name, inode)
		}
		cacheEntry(n.export, out)
	}
	fh, _, errno = n.wrapFile(fh, errno)
	return inode, fh, fuseFlags, errno
}

func (n *shareNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.export == nil {
		return nil, syscall.ESTALE
	}
	if errno := n.mutable(); errno != 0 {
		return nil, errno
	}
	inode, errno := n.LoopbackNode.Symlink(ctx, target, name, out)
	if errno == 0 {
		mapGuestOwner(n.export, &out.Attr)
		if n.export.coherence != nil {
			n.export.coherence.remember(n.EmbeddedInode(), name, inode)
		}
		cacheEntry(n.export, out)
	}
	return inode, errno
}

func (n *shareNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.export == nil {
		return nil, syscall.ESTALE
	}
	if errno := n.mutable(); errno != 0 {
		return nil, errno
	}
	other, ok := target.(*shareNode)
	if !ok || other.export != n.export {
		return nil, syscall.EXDEV
	}
	if kind := other.StableAttr().Mode & syscall.S_IFMT; kind != syscall.S_IFREG && kind != syscall.S_IFLNK {
		return nil, syscall.EPERM
	}
	st, errno := other.HostStat()
	if errno != 0 {
		return nil, errno
	}
	// A hard link would let the guest plant another host-visible device,
	// FIFO or socket entry without going through the denied MKNOD path.
	// Regular files and symlinks are the only linkable share policy types;
	// directories are rejected by the host kernel in any case.
	if kind := st.Mode & syscall.S_IFMT; kind != syscall.S_IFREG && kind != syscall.S_IFLNK {
		return nil, syscall.EPERM
	}
	inode, errno := n.LoopbackNode.Link(ctx, target, name, out)
	if errno == 0 {
		mapGuestOwner(n.export, &out.Attr)
		if n.export.coherence != nil {
			n.export.coherence.remember(n.EmbeddedInode(), name, inode)
		}
		cacheEntry(n.export, out)
	}
	return inode, errno
}

func (n *shareNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	if errno := n.available(); errno != 0 {
		return nil, errno
	}
	return n.LoopbackNode.Readlink(ctx)
}

func (n *shareNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if n.export == nil {
		return nil, 0, syscall.ESTALE
	}
	n.export.namespace.Lock()
	defer n.export.namespace.Unlock()
	if errno := n.available(); errno != 0 {
		return nil, 0, errno
	}
	if n.export.RO && flags&openWriteFlags != 0 {
		return nil, 0, syscall.EROFS
	}
	// StableAttr describes the inode the guest retained. Check it before any
	// path-based host open as defense in depth against a future inode-tree
	// synchronization regression; HostStat below separately checks the current
	// path target.
	switch n.StableAttr().Mode & syscall.S_IFMT {
	case syscall.S_IFREG, syscall.S_IFDIR, syscall.S_IFLNK:
	default:
		return nil, 0, syscall.EPERM
	}
	// Reject pre-existing special files before opening: opening a host
	// device node has side effects and must never be reachable from the
	// guest, and FIFOs/sockets are equally out of policy. Shares may
	// carry regular files, directories and symlinks only. HostStat is
	// fd-relative for pinned exports — an absolute Lstat here would be
	// denied inside a confined worker and this check would silently
	// fail open.
	st, errno := n.HostStat()
	if errno != 0 {
		return nil, 0, errno
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFREG, syscall.S_IFDIR, syscall.S_IFLNK:
	default:
		return nil, 0, syscall.EPERM
	}
	fh, fuseFlags, errno := n.LoopbackNode.Open(ctx, flags|guestONonblock)
	if errno == 0 {
		if errno = validateOpenedFile(ctx, fh, flags); errno != 0 {
			return nil, 0, errno
		}
	}
	wrapped, _, errno := n.wrapFile(fh, errno)
	return wrapped, fuseFlags, errno
}

func (n *shareNode) OpendirHandle(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if errno := n.available(); errno != 0 {
		return nil, 0, errno
	}
	if fd, ok := shareDirectoryCache(n.export).open(n.StableAttr().Ino); ok {
		ds, errno := fs.NewLoopbackDirStreamFd(fd)
		if errno == 0 {
			return &shareDirHandle{FileHandle: ds, export: n.export, node: n}, 0, 0
		}
		_ = syscall.Close(fd)
	}
	fh, fuseFlags, errno := n.LoopbackNode.OpendirHandle(ctx, flags)
	if errno != 0 || fh == nil {
		return nil, 0, errno
	}
	return &shareDirHandle{FileHandle: fh, export: n.export, node: n}, fuseFlags, 0
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
	errno := n.LoopbackNode.Getattr(ctx, f, out)
	if errno == 0 {
		mapGuestOwner(n.export, &out.Attr)
		if !n.isExportRoot() {
			cacheAttr(n.export, out)
		}
	}
	return errno
}

func (n *shareNode) Statx(ctx context.Context, f fs.FileHandle, flags uint32, mask uint32, out *fuse.StatxOut) syscall.Errno {
	if errno := n.available(); errno != 0 {
		return errno
	}
	statxer, ok := any(&n.LoopbackNode).(fs.NodeStatxer)
	if !ok {
		return syscall.ENOTSUP
	}
	errno := statxer.Statx(ctx, f, flags, mask, out)
	if errno == 0 {
		mapGuestStatxOwner(n.export, &out.Statx)
		if !n.isExportRoot() {
			cacheStatx(n.export, out)
		}
	}
	return errno
}

func (n *shareNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if n.export == nil {
		return syscall.ESTALE
	}
	n.export.namespace.Lock()
	defer n.export.namespace.Unlock()
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	switch n.StableAttr().Mode & syscall.S_IFMT {
	case syscall.S_IFREG, syscall.S_IFDIR:
	default:
		return syscall.EPERM
	}
	// A validated shareFile mutates its already-open regular file descriptor.
	// Every other path enters LoopbackNode's handle-less *at implementation;
	// validate its current target while guest namespace changes are excluded.
	opened, validatedHandle := f.(*shareFile)
	if validatedHandle && opened.export != n.export {
		return syscall.EBADF
	}
	if !validatedHandle {
		st, errno := n.HostStat()
		if errno != 0 {
			return errno
		}
		switch st.Mode & syscall.S_IFMT {
		case syscall.S_IFREG, syscall.S_IFDIR:
		default:
			return syscall.EPERM
		}
	}
	errno := n.LoopbackNode.Setattr(ctx, f, in, out)
	// Ownership squash, as in NewFS: gVisor's gofer chowns every file it
	// creates, and non-root hosts cannot chown. Ownership is cosmetic on a
	// host share; apply all other requested attribute changes.
	if errno == 0 {
		mapGuestOwner(n.export, &out.Attr)
		return 0
	}
	if errno != syscall.EPERM && errno != syscall.EACCES {
		return errno
	}
	if in.Valid&(fuse.FATTR_UID|fuse.FATTR_GID) == 0 {
		return errno
	}
	retry := *in
	retry.Valid &^= fuse.FATTR_UID | fuse.FATTR_GID
	if retry.Valid != 0 {
		errno = n.LoopbackNode.Setattr(ctx, f, &retry, out)
		if errno == 0 {
			mapGuestOwner(n.export, &out.Attr)
		}
		return errno
	}
	errno = n.LoopbackNode.Getattr(ctx, f, out)
	if errno == 0 {
		mapGuestOwner(n.export, &out.Attr)
	}
	return errno
}

// xattrWriteAllowed permits only user.* attributes. security.*
// (capabilities, LSM labels), trusted.* and system.* (ACLs) are written
// with the VMM's host credentials and must never cross the guest boundary.
func xattrWriteAllowed(attr string) bool {
	return strings.HasPrefix(attr, "user.")
}

func (n *shareNode) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	if n.export == nil {
		return 0, syscall.ESTALE
	}
	n.export.namespace.Lock()
	defer n.export.namespace.Unlock()
	if errno := n.available(); errno != 0 {
		return 0, errno
	}
	return n.LoopbackNode.Getxattr(ctx, attr, dest)
}

func (n *shareNode) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	if n.export == nil {
		return 0, syscall.ESTALE
	}
	n.export.namespace.Lock()
	defer n.export.namespace.Unlock()
	if errno := n.available(); errno != 0 {
		return 0, errno
	}
	return n.LoopbackNode.Listxattr(ctx, dest)
}

func (n *shareNode) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	if n.export == nil {
		return syscall.ESTALE
	}
	n.export.namespace.Lock()
	defer n.export.namespace.Unlock()
	if errno := n.mutable(); errno != 0 {
		return errno
	}
	if !xattrWriteAllowed(attr) {
		return syscall.EPERM
	}
	return n.LoopbackNode.Setxattr(ctx, attr, data, flags)
}

func (n *shareNode) Removexattr(ctx context.Context, attr string) syscall.Errno {
	if n.export == nil {
		return syscall.ESTALE
	}
	n.export.namespace.Lock()
	defer n.export.namespace.Unlock()
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
