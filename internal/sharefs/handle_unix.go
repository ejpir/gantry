//go:build linux || darwin

package sharefs

import (
	"context"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// shareFile gates handle operations after a forced revoke. It deliberately
// does not expose PassthroughFd: kernel-side passthrough would bypass this
// security gate.
type shareFile struct {
	fs.FileHandle
	export *Export
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
		cacheAttr(f.export, out)
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
		cacheAttr(f.export, out)
	}
	return errno
}

func (f *shareFile) Flush(ctx context.Context) syscall.Errno {
	if errno := f.available(); errno != 0 {
		return errno
	}
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
	// Host advisory locks are not a share capability. Forwarding them leaks
	// host lock state and lets a guest interfere with unrelated host users.
	return syscall.ENOTSUP
}

func (f *shareFile) Setlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	if errno := f.available(); errno != 0 {
		return errno
	}
	return syscall.ENOTSUP
}

func (f *shareFile) Setlkw(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	if errno := f.available(); errno != 0 {
		return errno
	}
	// In particular, never enter the host's blocking F_SETLKW path: FUSE
	// cancellation cannot interrupt that syscall, so it would pin the hub's
	// request guard and deadlock revocation/daemon shutdown indefinitely.
	return syscall.ENOTSUP
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
		cacheStatx(f.export, out)
	}
	return errno
}

// shareDirStream covers Readdir; shareDirHandle covers the OpendirHandle path.
type shareDirStream struct {
	fs.DirStream
	export *Export
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
	export *Export
	node   *shareNode
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

func (d *shareDirHandle) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if !d.available() || d.node == nil {
		return nil, syscall.ESTALE
	}
	provider, ok := d.FileHandle.(interface {
		GantryDirFD() (int, bool)
	})
	if !ok {
		return d.node.Lookup(ctx, name, out)
	}
	dirFD, ok := provider.GantryDirFD()
	if !ok {
		return nil, syscall.EBADF
	}
	inode, errno := d.node.LookupAt(ctx, dirFD, name, out)
	if errno == 0 {
		mapGuestOwner(d.export, &out.Attr)
		if d.export.coherence != nil {
			d.export.coherence.remember(d.node.EmbeddedInode(), name, inode)
		}
		cacheEntry(d.export, out)
		if out.Mode&syscall.S_IFMT == syscall.S_IFDIR {
			shareDirectoryCache(d.export).prefetch(
				inode.StableAttr().Ino, d.node.StableAttr().Ino, dirFD, name, out.Ino,
			)
		}
	}
	return inode, errno
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
func mapGuestOwner(e *Export, attr *fuse.Attr) {
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

func mapGuestStatxOwner(e *Export, attr *fuse.Statx) {
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
