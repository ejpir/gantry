//go:build linux || darwin

package virtio

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// This file is the Unix half of the share hub: the loopback backend over a
// pinned root descriptor and its node/file policy wrappers. The export
// lifecycle, synthetic namespace root, and device transport are
// platform-neutral and live in vsharehub_common.go.

// shareOwnerMappingSupported: the unix loopback wrapper rewrites owner
// fields via mapGuestOwner, so uid=/gid= exports are honored.
const shareOwnerMappingSupported = true

// newExportNode pins path beneath an open root descriptor and builds the
// loopback node presented as the export root. The returned release func
// drops the pinned root when the export finishes. It is hub-agnostic so
// the one-shot share path reuses the exact same confinement as hub exports.
func newExportNode(exp *ShareExport, path string, salt uint64) (fs.InodeEmbedder, string, func(), error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", nil, fmt.Errorf("resolve share path: %w", err)
	}
	rootFD, err := os.Open(abs)
	if err != nil {
		return nil, "", nil, fmt.Errorf("open share root: %w", err)
	}
	st, err := rootFD.Stat()
	if err != nil || !st.IsDir() {
		_ = rootFD.Close()
		if err == nil {
			err = fmt.Errorf("not a directory")
		}
		return nil, "", nil, fmt.Errorf("share root %s: %w", abs, err)
	}
	rootNode, err := fs.NewLoopbackRootFD(abs, int(rootFD.Fd()))
	if err != nil {
		_ = rootFD.Close()
		return nil, "", nil, fmt.Errorf("create loopback export: %w", err)
	}
	ln, ok := rootNode.(*fs.LoopbackNode)
	if !ok {
		_ = rootFD.Close()
		return nil, "", nil, fmt.Errorf("unexpected loopback root %T", rootNode)
	}
	ln.RootData.InoSalt = salt
	rootData := ln.RootData
	node := &shareNode{LoopbackNode: fs.LoopbackNode{RootData: rootData}, export: exp}
	rootData.RootNode = node
	release := func() { _ = rootFD.Close() }
	return node, ln.RootData.RootPrefix, release, nil
}

// NewShareNodeFS builds the root for a one-shot share device with exactly
// the hub export policy: pinned root descriptor, default-deny ioctls, MKNOD
// and xattrs, special-file rejection, ownership squash and host-enforced
// read-only. The legacy LoopbackNode+squashNode backend is retired so
// `gantry run/exec -share` gets the same confinement as persistent hub
// exports. The pinned descriptor closes when the kernel forgets the root
// (unmount / device teardown) via shareNode.OnForget.
func NewShareNodeFS(root string, readonly bool) (fs.InodeEmbedder, error) {
	exp := &ShareExport{Tag: "share", RO: readonly}
	exp.state.Store(int32(ShareExportActive))
	node, finalPath, release, err := newExportNode(exp, root, 1<<32)
	if err != nil {
		return nil, err
	}
	exp.Path = finalPath
	exp.node = node
	exp.release = release
	return node, nil
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
	inode, errno := n.LoopbackNode.Lookup(ctx, name, out)
	if errno == 0 {
		mapGuestOwner(n.export, &out.Attr)
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
	if errno := n.mutable(); errno != 0 {
		return nil, errno
	}
	inode, errno := n.LoopbackNode.Mkdir(ctx, name, mode, out)
	if errno == 0 {
		mapGuestOwner(n.export, &out.Attr)
	}
	return inode, errno
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
	if errno == 0 {
		mapGuestOwner(n.export, &out.Attr)
	}
	fh, _, errno = n.wrapFile(fh, errno)
	return inode, fh, fuseFlags, errno
}

func (n *shareNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.mutable(); errno != 0 {
		return nil, errno
	}
	inode, errno := n.LoopbackNode.Symlink(ctx, target, name, out)
	if errno == 0 {
		mapGuestOwner(n.export, &out.Attr)
	}
	return inode, errno
}

func (n *shareNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if errno := n.mutable(); errno != 0 {
		return nil, errno
	}
	if other, ok := target.(*shareNode); ok && other.export != n.export {
		return nil, syscall.EXDEV
	}
	inode, errno := n.LoopbackNode.Link(ctx, target, name, out)
	if errno == 0 {
		mapGuestOwner(n.export, &out.Attr)
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
	if errno := n.available(); errno != 0 {
		return nil, 0, errno
	}
	if n.export.RO && flags&openWriteFlags != 0 {
		return nil, 0, syscall.EROFS
	}
	// Reject pre-existing special files before opening: opening a host
	// device node has side effects and must never be reachable from the
	// guest, and FIFOs/sockets are equally out of policy. Shares may
	// carry regular files, directories and symlinks only.
	var st syscall.Stat_t
	if err := syscall.Lstat(n.HostPath(), &st); err == nil {
		switch st.Mode & syscall.S_IFMT {
		case syscall.S_IFREG, syscall.S_IFDIR, syscall.S_IFLNK:
		default:
			return nil, 0, syscall.EPERM
		}
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
	errno := n.LoopbackNode.Getattr(ctx, f, out)
	if errno == 0 {
		mapGuestOwner(n.export, &out.Attr)
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
	}
	return errno
}

func (n *shareNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if errno := n.mutable(); errno != 0 {
		return errno
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
	errno := g.Getattr(ctx, out)
	if errno == 0 {
		mapGuestOwner(f.export, &out.Attr)
	}
	return errno
}

func (f *shareFile) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if errno := f.mutable(); errno != 0 {
		return errno
	}
	s, ok := f.FileHandle.(fs.FileSetattrer)
	if !ok {
		return syscall.ENOTSUP
	}
	errno := s.Setattr(ctx, in, out)
	if (errno == syscall.EPERM || errno == syscall.EACCES) && in.Valid&(fuse.FATTR_UID|fuse.FATTR_GID) != 0 {
		retry := *in
		retry.Valid &^= fuse.FATTR_UID | fuse.FATTR_GID
		if retry.Valid != 0 {
			errno = s.Setattr(ctx, &retry, out)
		} else if g, ok := f.FileHandle.(fs.FileGetattrer); ok {
			errno = g.Getattr(ctx, out)
		}
	}
	if errno == 0 {
		mapGuestOwner(f.export, &out.Attr)
	}
	return errno
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
	errno := s.Statx(ctx, flags, mask, out)
	if errno == 0 {
		mapGuestStatxOwner(f.export, &out.Statx)
	}
	return errno
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

// mapGuestOwner rewrites only the numeric ownership reported to the guest.
// The host inode and all host-side access checks remain unchanged.
func mapGuestOwner(e *ShareExport, attr *fuse.Attr) {
	if e == nil || attr == nil {
		return
	}
	if e.UID != nil {
		attr.Uid = *e.UID
	}
	if e.GID != nil {
		attr.Gid = *e.GID
	}
}

func mapGuestStatxOwner(e *ShareExport, attr *fuse.Statx) {
	if e == nil || attr == nil {
		return
	}
	if e.UID != nil {
		attr.Uid = *e.UID
	}
	if e.GID != nil {
		attr.Gid = *e.GID
	}
}
