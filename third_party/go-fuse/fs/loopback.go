//go:build !windows

// Copyright 2019 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/hanwen/go-fuse/v2/internal/openat"
	"github.com/hanwen/go-fuse/v2/internal/renameat"
	"golang.org/x/sys/unix"
)

// LoopbackRoot holds the parameters for creating a new loopback
// filesystem. Loopback filesystem delegate their operations to an
// underlying POSIX file system.
type LoopbackRoot struct {
	// The path to the root of the underlying file system.
	Path string

	// The device on which the Path resides. This must be set if
	// the underlying filesystem crosses file systems.
	Dev uint64

	// RootPrefix is the canonical host path used for escape checks when
	// Path itself is a pinned /proc/self/fd or /dev/fd handle. Empty means
	// Path is also the comparison root.
	RootPrefix string

	// RootFD, when non-negative, pins the directory descriptor backing Path.
	// Darwin resolves it with F_GETPATH for every operation because /dev/fd
	// does not reliably behave as a directory symlink there; Linux uses Path's
	// /proc/self/fd entry directly.
	RootFD int

	// InoSalt namespaces StableAttr inode numbers when the same host file can
	// be reached through two independently confined exports (for example via
	// a pre-existing hard link). Zero preserves the traditional mapping.
	InoSalt uint64

	// NewNode returns a new InodeEmbedder to be used to respond
	// to a LOOKUP/CREATE/MKDIR/MKNOD opcode. If not set, use a
	// LoopbackNode.
	//
	// Deprecated: use NodeWrapChilder instead.
	NewNode func(rootData *LoopbackRoot, parent *Inode, name string, st *syscall.Stat_t) InodeEmbedder

	// RootNode is the root of the Loopback. This must be set if
	// the Loopback file system is not the root of the FUSE
	// mount. It is set automatically by NewLoopbackRoot.
	RootNode InodeEmbedder
}

func (r *LoopbackRoot) newNode(parent *Inode, name string, st *syscall.Stat_t) InodeEmbedder {
	if r.NewNode != nil {
		return r.NewNode(r, parent, name, st)
	}
	return &LoopbackNode{
		RootData: r,
	}
}

func (r *LoopbackRoot) idFromStat(st *syscall.Stat_t) StableAttr {
	// We compose an inode number by the underlying inode, and
	// mixing in the device number. In traditional filesystems,
	// the inode numbers are small. The device numbers are also
	// small (typically 16 bit). Finally, we mask out the root
	// device number of the root, so a loopback FS that does not
	// encompass multiple mounts will reflect the inode numbers of
	// the underlying filesystem
	swapped := (uint64(st.Dev) << 32) | (uint64(st.Dev) >> 32)
	swappedRootDev := (r.Dev << 32) | (r.Dev >> 32)
	return StableAttr{
		Mode: uint32(st.Mode),
		Gen:  1,
		// This should work well for traditional backing FSes,
		// not so much for other go-fuse FS-es
		Ino: ((swapped ^ swappedRootDev) ^ st.Ino) ^ r.InoSalt,
	}
}

// LoopbackNode is a filesystem node in a loopback file system. It is
// public so it can be used as a basis for other loopback based
// filesystems. See NewLoopbackFile or LoopbackRoot for more
// information.
type LoopbackNode struct {
	Inode

	// RootData points back to the root of the loopback filesystem.
	RootData *LoopbackRoot
}

// loopbackNodeEmbedder can only be implemented by the LoopbackNode
// concrete type.
type loopbackNodeEmbedder interface {
	loopbackNode() *LoopbackNode
}

func (n *LoopbackNode) loopbackNode() *LoopbackNode {
	return n
}

var _ = (NodeStatfser)((*LoopbackNode)(nil))

func (n *LoopbackNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	s := syscall.Statfs_t{}
	if n.pinned() {
		dirfd, err := openRelDir(n.RootData.RootFD, n.relPath())
		if err != nil {
			return ToErrno(err)
		}
		defer unix.Close(dirfd)
		var us unix.Statfs_t
		if err := unix.Fstatfs(dirfd, &us); err != nil {
			return ToErrno(err)
		}
		s = statfsToSyscall(&us)
	} else {
		p, errno := n.securePath("")
		if errno != 0 {
			return errno
		}
		if err := syscall.Statfs(p, &s); err != nil {
			return ToErrno(err)
		}
	}
	out.FromStatfsT(&s)
	return OK
}

// path returns the full path to the file in the underlying file
// system.
func (n *LoopbackNode) root() *Inode {
	var rootNode *Inode
	if n.RootData.RootNode != nil {
		rootNode = n.RootData.RootNode.EmbeddedInode()
	} else {
		rootNode = n.Root()
	}

	return rootNode
}

// relativePath returns the path the node, relative to to the root directory
func (n *LoopbackNode) relativePath() string {
	return n.Path(n.root())
}

// rootPath returns the export root path. With a pinned root descriptor it
// resolves through the descriptor (F_GETPATH on Darwin, /proc/self/fd on
// Linux), so renaming the exported root and planting a replacement at the
// original path cannot retarget operations at the replacement directory.
func (n *LoopbackNode) rootPath() string {
	if n.RootData.RootFD >= 0 {
		return loopbackRootFDPath(n.RootData.RootFD, n.RootData.Path)
	}
	return n.RootData.Path
}

// path returns the absolute path to the node
func (n *LoopbackNode) path() string {
	return filepath.Join(n.rootPath(), n.relativePath())
}

// HostPath exposes the node's resolved host path (via the pinned root
// when available) for gantry's policy wrappers, which must inspect the
// host file type before opening it.
func (n *LoopbackNode) HostPath() string { return n.path() }

// securePath resolves n's directory through any symlinks and refuses to
// operate once the node has escaped the exported root through an
// intermediate symlink swap (a guest can rename a directory aside and plant
// a symlink at its old name, then descend through it). If name is non-empty
// it is appended WITHOUT resolving it, so final-component semantics (Lstat,
// Readlink, Unlink on a symlink) are preserved. gantry serializes FUSE
// requests on the virtio transport lock, so resolve-then-act cannot be
// raced from the guest side.
func (n *LoopbackNode) securePath(name string) (string, syscall.Errno) {
	root := n.rootPath()
	compareRoot := root
	if n.RootData.RootPrefix != "" && n.RootData.RootFD < 0 {
		var err error
		compareRoot, err = filepath.EvalSymlinks(root)
		if err != nil {
			return "", ToErrno(err)
		}
	}
	dir := filepath.Join(root, n.relativePath())
	base := ""
	if name != "" {
		base = name
	} else if dir == root {
		return root, OK // the root itself: nothing above it to verify
	} else {
		dir, base = filepath.Dir(dir), filepath.Base(dir)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", ToErrno(err)
	}
	if resolved != compareRoot && !strings.HasPrefix(resolved, compareRoot+string(filepath.Separator)) {
		return "", syscall.EACCES
	}
	if base == "" {
		return resolved, OK
	}
	return filepath.Join(resolved, base), OK
}

var _ = (NodeLookuper)((*LoopbackNode)(nil))

func (n *LoopbackNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	var st syscall.Stat_t
	if n.pinned() {
		var errno syscall.Errno
		st, errno = lstatRel(n.RootData.RootFD, relJoin(n.relPath(), name))
		if errno != 0 {
			return nil, errno
		}
	} else {
		p, errno := n.securePath(name)
		if errno != 0 {
			return nil, errno
		}
		if err := syscall.Lstat(p, &st); err != nil {
			return nil, ToErrno(err)
		}
	}
	return n.newLookupChild(ctx, name, &st, out), 0
}

// LookupAt performs the LOOKUP half of READDIRPLUS relative to an already
// pinned directory descriptor. It preserves final-component no-follow
// semantics while avoiding another root-to-parent path walk for every entry.
func (n *LoopbackNode) LookupAt(ctx context.Context, dirFD int, name string, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	if dirFD < 0 || name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
		return nil, syscall.EINVAL
	}
	var raw unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &raw, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, ToErrno(err)
	}
	st := statToSyscall(&raw)
	return n.newLookupChild(ctx, name, &st, out), 0
}

func (n *LoopbackNode) newLookupChild(ctx context.Context, name string, st *syscall.Stat_t, out *fuse.EntryOut) *Inode {
	out.Attr.FromStat(st)
	node := n.RootData.newNode(n.EmbeddedInode(), name, st)
	return n.NewInode(ctx, node, n.RootData.idFromStat(st))
}

// preserveOwner sets uid and gid of `path` according to the caller information
// in `ctx`.
func (n *LoopbackNode) preserveOwner(ctx context.Context, path string) error {
	if os.Getuid() != 0 {
		return nil
	}
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		return nil
	}
	return syscall.Lchown(path, int(caller.Uid), int(caller.Gid))
}

var _ = (NodeMknoder)((*LoopbackNode)(nil))

func (n *LoopbackNode) Mknod(ctx context.Context, name string, mode, rdev uint32, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	if n.pinned() {
		return n.mknodAt(ctx, name, mode, rdev, out)
	}
	p, errno := n.securePath(name)
	if errno != 0 {
		return nil, errno
	}
	err := syscall.Mknod(p, mode, intDev(rdev))
	if err != nil {
		return nil, ToErrno(err)
	}
	n.preserveOwner(ctx, p)
	st := syscall.Stat_t{}
	if err := syscall.Lstat(p, &st); err != nil {
		syscall.Unlink(p)
		return nil, ToErrno(err)
	}

	out.Attr.FromStat(&st)

	node := n.RootData.newNode(n.EmbeddedInode(), name, &st)
	ch := n.NewInode(ctx, node, n.RootData.idFromStat(&st))

	return ch, 0
}

var _ = (NodeMkdirer)((*LoopbackNode)(nil))

func (n *LoopbackNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	if n.pinned() {
		return n.mkdirAt(ctx, name, mode, out)
	}
	p, errno := n.securePath(name)
	if errno != 0 {
		return nil, errno
	}
	err := os.Mkdir(p, os.FileMode(mode))
	if err != nil {
		return nil, ToErrno(err)
	}
	n.preserveOwner(ctx, p)
	st := syscall.Stat_t{}
	if err := syscall.Lstat(p, &st); err != nil {
		syscall.Rmdir(p)
		return nil, ToErrno(err)
	}

	out.Attr.FromStat(&st)

	node := n.RootData.newNode(n.EmbeddedInode(), name, &st)
	ch := n.NewInode(ctx, node, n.RootData.idFromStat(&st))

	return ch, 0
}

var _ = (NodeRmdirer)((*LoopbackNode)(nil))

func (n *LoopbackNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	if n.pinned() {
		return withParentAt(n.RootData.RootFD, relJoin(n.relPath(), name),
			func(dirfd int, base string) error {
				return unix.Unlinkat(dirfd, base, unix.AT_REMOVEDIR)
			})
	}
	p, errno := n.securePath(name)
	if errno != 0 {
		return errno
	}
	err := syscall.Rmdir(p)
	return ToErrno(err)
}

var _ = (NodeUnlinker)((*LoopbackNode)(nil))

func (n *LoopbackNode) Unlink(ctx context.Context, name string) syscall.Errno {
	if n.pinned() {
		return withParentAt(n.RootData.RootFD, relJoin(n.relPath(), name),
			func(dirfd int, base string) error {
				return unix.Unlinkat(dirfd, base, 0)
			})
	}
	p, errno := n.securePath(name)
	if errno != 0 {
		return errno
	}
	err := syscall.Unlink(p)
	return ToErrno(err)
}

var _ = (NodeRenamer)((*LoopbackNode)(nil))

func (n *LoopbackNode) Rename(ctx context.Context, name string, newParent InodeEmbedder, newName string, flags uint32) syscall.Errno {
	e2, ok := newParent.(loopbackNodeEmbedder)
	if !ok {
		return syscall.EXDEV
	}

	if e2.loopbackNode().RootData != n.RootData {
		return syscall.EXDEV
	}

	if flags != 0 {
		return n.rename2(name, e2.loopbackNode(), newName, flags)
	}

	if n.pinned() {
		return n.renameAt(name, e2.loopbackNode(), newName)
	}

	p1, errno := n.securePath(name)
	if errno != 0 {
		return errno
	}
	p2, errno := e2.loopbackNode().securePath(newName)
	if errno != 0 {
		return errno
	}

	err := syscall.Rename(p1, p2)
	return ToErrno(err)
}

var _ = (NodeCreater)((*LoopbackNode)(nil))

func (n *LoopbackNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *Inode, fh FileHandle, fuseFlags uint32, errno syscall.Errno) {
	if n.pinned() {
		return n.createAt(ctx, name, flags, mode, out)
	}
	p, errno := n.securePath(name)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	hostFlags := openFlagsToHost(flags) &^ syscall.O_APPEND
	f, err := os.OpenFile(p, hostFlags|os.O_CREATE, os.FileMode(mode))
	if err != nil {
		return nil, nil, 0, ToErrno(err)
	}
	n.preserveOwner(ctx, p)
	st := syscall.Stat_t{}
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		f.Close()
		return nil, nil, 0, ToErrno(err)
	}

	node := n.RootData.newNode(n.EmbeddedInode(), name, &st)
	ch := n.NewInode(ctx, node, n.RootData.idFromStat(&st))
	lf := NewLoopbackFileFromOS(f)

	out.FromStat(&st)
	return ch, lf, 0, 0
}

func (n *LoopbackNode) rename2(name string, newParent *LoopbackNode, newName string, flags uint32) syscall.Errno {
	var fd1, fd2 int
	var err error
	if n.pinned() {
		fd1, err = openRelDir(n.RootData.RootFD, n.relPath())
	} else {
		p1, errno := n.securePath("")
		if errno != 0 {
			return errno
		}
		fd1, err = syscall.Open(p1, syscall.O_DIRECTORY, 0)
	}
	if err != nil {
		return ToErrno(err)
	}
	defer syscall.Close(fd1)
	if newParent.pinned() {
		fd2, err = openRelDir(newParent.RootData.RootFD, newParent.relPath())
	} else {
		p2, errno := newParent.securePath("")
		if errno != 0 {
			return errno
		}
		fd2, err = syscall.Open(p2, syscall.O_DIRECTORY, 0)
	}
	if err != nil {
		return ToErrno(err)
	}
	defer syscall.Close(fd2)

	var st syscall.Stat_t
	if err := syscall.Fstat(fd1, &st); err != nil {
		return ToErrno(err)
	}

	// Double check that nodes didn't change from under us.
	if n.root() != n.EmbeddedInode() && n.Inode.StableAttr().Ino != n.RootData.idFromStat(&st).Ino {
		return syscall.EBUSY
	}
	if err := syscall.Fstat(fd2, &st); err != nil {
		return ToErrno(err)
	}

	if (newParent.root() != newParent.EmbeddedInode()) && newParent.Inode.StableAttr().Ino != n.RootData.idFromStat(&st).Ino {
		return syscall.EBUSY
	}

	hostFlags, errno := renameFlagsToHost(flags)
	if errno != 0 {
		return errno
	}
	return ToErrno(renameat.Renameat(fd1, name, fd2, newName, hostFlags))
}

var _ = (NodeSymlinker)((*LoopbackNode)(nil))

func (n *LoopbackNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	// NOTE: target is intentionally NOT validated — a symlink may point
	// anywhere; what matters is that gantry never FOLLOWS one out of the
	// share (pinned-root *at walk with O_NOFOLLOW on every op).
	if n.pinned() {
		return n.symlinkAt(ctx, target, name, out)
	}
	p, errno := n.securePath(name)
	if errno != 0 {
		return nil, errno
	}
	err := syscall.Symlink(target, p)
	if err != nil {
		return nil, ToErrno(err)
	}
	n.preserveOwner(ctx, p)
	st := syscall.Stat_t{}
	if err := syscall.Lstat(p, &st); err != nil {
		syscall.Unlink(p)
		return nil, ToErrno(err)
	}
	node := n.RootData.newNode(n.EmbeddedInode(), name, &st)
	ch := n.NewInode(ctx, node, n.RootData.idFromStat(&st))

	out.Attr.FromStat(&st)
	return ch, 0
}

var _ = (NodeLinker)((*LoopbackNode)(nil))

func (n *LoopbackNode) Link(ctx context.Context, target InodeEmbedder, name string, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	e2, ok := target.(loopbackNodeEmbedder)
	if !ok {
		return nil, syscall.EXDEV
	}

	if e2.loopbackNode().RootData != n.RootData {
		return nil, syscall.EXDEV
	}

	if n.pinned() {
		return n.linkAt(ctx, e2.loopbackNode(), name, out)
	}

	p, errno := n.securePath(name)
	if errno != 0 {
		return nil, errno
	}
	oldPath, errno := e2.loopbackNode().securePath("")
	if errno != 0 {
		return nil, errno
	}
	err := syscall.Link(oldPath, p)
	if err != nil {
		return nil, ToErrno(err)
	}
	st := syscall.Stat_t{}
	if err := syscall.Lstat(p, &st); err != nil {
		syscall.Unlink(p)
		return nil, ToErrno(err)
	}
	node := n.RootData.newNode(n.EmbeddedInode(), name, &st)
	ch := n.NewInode(ctx, node, n.RootData.idFromStat(&st))

	out.Attr.FromStat(&st)
	return ch, 0
}

var _ = (NodeReadlinker)((*LoopbackNode)(nil))

func (n *LoopbackNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	if n.pinned() {
		var out []byte
		errno := withParentAt(n.RootData.RootFD, n.relPath(), func(dirfd int, base string) error {
			for l := 256; ; l *= 2 {
				buf := make([]byte, l)
				sz, err := unix.Readlinkat(dirfd, base, buf)
				if err != nil {
					return err
				}
				if sz < len(buf) {
					out = buf[:sz]
					return nil
				}
			}
		})
		return out, errno
	}
	p, errno := n.securePath("")
	if errno != 0 {
		return nil, errno
	}

	for l := 256; ; l *= 2 {
		buf := make([]byte, l)
		sz, err := syscall.Readlink(p, buf)
		if err != nil {
			return nil, ToErrno(err)
		}

		if sz < len(buf) {
			return buf[:sz], 0
		}
	}
}

var _ = (NodeOpener)((*LoopbackNode)(nil))

// Symlink-safe: pinned exports walk from the root descriptor with
// O_NOFOLLOW on every component including the final one.
func (n *LoopbackNode) Open(ctx context.Context, flags uint32) (fh FileHandle, fuseFlags uint32, errno syscall.Errno) {
	flags = flags &^ fuse.FMODE_EXEC
	hostFlags := openFlagsToHost(flags) &^ syscall.O_APPEND

	if n.pinned() {
		var fd int = -1
		errno := withParentAt(n.RootData.RootFD, n.relPath(), func(dirfd int, base string) error {
			var err error
			fd, err = unix.Openat(dirfd, base, hostFlags|unix.O_NOFOLLOW, 0)
			return err
		})
		if errno != 0 {
			return nil, 0, errno
		}
		return NewLoopbackFile(fd), 0, 0
	}

	f, err := openat.OpenSymlinkAware(n.rootPath(), n.relativePath(), hostFlags, 0)
	if err != nil {
		return nil, 0, ToErrno(err)
	}
	lf := NewLoopbackFile(f)
	return lf, 0, 0
}

var _ = (NodeOpendirHandler)((*LoopbackNode)(nil))

func (n *LoopbackNode) OpendirHandle(ctx context.Context, flags uint32) (FileHandle, uint32, syscall.Errno) {
	if n.pinned() {
		dirfd, err := openRelDir(n.RootData.RootFD, n.relPath())
		if err != nil {
			return nil, 0, ToErrno(err)
		}
		ds, errno := NewLoopbackDirStreamFd(dirfd)
		if errno != 0 {
			unix.Close(dirfd)
			return nil, 0, errno
		}
		return ds, 0, 0
	}
	p, gerrno := n.securePath("")
	if gerrno != 0 {
		return nil, 0, gerrno
	}
	ds, errno := NewLoopbackDirStream(p)
	if errno != 0 {
		return nil, 0, errno
	}
	return ds, 0, errno
}

var _ = (NodeReaddirer)((*LoopbackNode)(nil))

func (n *LoopbackNode) Readdir(ctx context.Context) (DirStream, syscall.Errno) {
	if n.pinned() {
		dirfd, err := openRelDir(n.RootData.RootFD, n.relPath())
		if err != nil {
			return nil, ToErrno(err)
		}
		ds, errno := NewLoopbackDirStreamFd(dirfd)
		if errno != 0 {
			unix.Close(dirfd)
			return nil, errno
		}
		return ds, 0
	}
	p, errno := n.securePath("")
	if errno != 0 {
		return nil, errno
	}
	return NewLoopbackDirStream(p)
}

var _ = (NodeGetattrer)((*LoopbackNode)(nil))

func (n *LoopbackNode) Getattr(ctx context.Context, f FileHandle, out *fuse.AttrOut) syscall.Errno {
	if f != nil {
		if fga, ok := f.(FileGetattrer); ok {
			return fga.Getattr(ctx, out)
		}
	}

	if n.pinned() {
		st, errno := lstatRel(n.RootData.RootFD, n.relPath())
		if errno != 0 {
			return errno
		}
		out.FromStat(&st)
		return OK
	}

	p, errno := n.securePath("")
	if errno != 0 {
		return errno
	}

	var err error
	st := syscall.Stat_t{}
	if &n.Inode == n.root() {
		err = syscall.Stat(p, &st)
	} else {
		err = syscall.Lstat(p, &st)
	}

	if err != nil {
		return ToErrno(err)
	}
	out.FromStat(&st)
	return OK
}

var _ = (NodeSetattrer)((*LoopbackNode)(nil))

func (n *LoopbackNode) Setattr(ctx context.Context, f FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if n.pinned() {
		return n.setattrAt(ctx, f, in, out)
	}
	p, errno := n.securePath("")
	if errno != 0 {
		return errno
	}
	fsa, ok := f.(FileSetattrer)
	if ok && fsa != nil {
		if errno := fsa.Setattr(ctx, in, out); errno != 0 {
			return errno
		}
	} else {
		if m, ok := in.GetMode(); ok {
			if err := syscall.Chmod(p, m); err != nil {
				return ToErrno(err)
			}
		}

		uid, uok := in.GetUID()
		gid, gok := in.GetGID()
		if uok || gok {
			suid := -1
			sgid := -1
			if uok {
				suid = int(uid)
			}
			if gok {
				sgid = int(gid)
			}
			if err := unix.Fchownat(unix.AT_FDCWD, p, suid, sgid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return ToErrno(err)
			}
		}

		// Truncate before setting times, so an explicit mtime is
		// not clobbered by the truncate.
		if sz, ok := in.GetSize(); ok {
			if err := syscall.Truncate(p, int64(sz)); err != nil {
				return ToErrno(err)
			}
		}

		mtime, mok := in.GetMTime()
		atime, aok := in.GetATime()

		if mok || aok {
			ta := unix.Timespec{Nsec: unix_UTIME_OMIT}
			tm := unix.Timespec{Nsec: unix_UTIME_OMIT}
			var err error
			if aok {
				ta, err = unix.TimeToTimespec(atime)
				if err != nil {
					return ToErrno(err)
				}
			}
			if mok {
				tm, err = unix.TimeToTimespec(mtime)
				if err != nil {
					return ToErrno(err)
				}
			}
			ts := []unix.Timespec{ta, tm}
			if err := unix.UtimesNanoAt(unix.AT_FDCWD, p, ts, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return ToErrno(err)
			}
		}
	}

	fga, ok := f.(FileGetattrer)
	if ok && fga != nil {
		fga.Getattr(ctx, out)
	} else {
		st := syscall.Stat_t{}
		err := syscall.Lstat(p, &st)
		if err != nil {
			return ToErrno(err)
		}
		out.FromStat(&st)
	}
	return OK
}

var _ = (NodeGetxattrer)((*LoopbackNode)(nil))

func (n *LoopbackNode) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	if n.pinned() {
		var size int
		errno := n.withPinnedXattr(func(fd int) error {
			var err error
			size, err = unix.Fgetxattr(fd, attr, dest)
			return err
		})
		if errno != 0 {
			return 0, errno
		}
		return uint32(size), 0
	}
	p, errno := n.securePath("")
	if errno != 0 {
		return 0, errno
	}
	sz, err := unix.Lgetxattr(p, attr, dest)
	if err != nil {
		return 0, ToErrno(err)
	}
	return uint32(sz), 0
}

var _ = (NodeSetxattrer)((*LoopbackNode)(nil))

func (n *LoopbackNode) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	if n.pinned() {
		return n.withPinnedXattr(func(fd int) error {
			return unix.Fsetxattr(fd, attr, data, xattrFlagsToHost(flags))
		})
	}
	p, errno := n.securePath("")
	if errno != 0 {
		return errno
	}
	err := unix.Lsetxattr(p, attr, data, xattrFlagsToHost(flags))
	return ToErrno(err)
}

var _ = (NodeRemovexattrer)((*LoopbackNode)(nil))

func (n *LoopbackNode) Removexattr(ctx context.Context, attr string) syscall.Errno {
	if n.pinned() {
		return n.withPinnedXattr(func(fd int) error {
			return unix.Fremovexattr(fd, attr)
		})
	}
	p, errno := n.securePath("")
	if errno != 0 {
		return errno
	}
	err := unix.Lremovexattr(p, attr)
	return ToErrno(err)
}

var _ = (NodeCopyFileRanger)((*LoopbackNode)(nil))

func (n *LoopbackNode) CopyFileRange(ctx context.Context, fhIn FileHandle,
	offIn uint64, out *Inode, fhOut FileHandle, offOut uint64,
	len uint64, flags uint64) (count uint32, errno syscall.Errno) {
	lfIn, ok := fhIn.(*LoopbackFile)
	if !ok {
		return 0, unix.ENOTSUP
	}
	lfOut, ok := fhOut.(*LoopbackFile)
	if !ok {
		return 0, unix.ENOTSUP
	}
	signedOffIn := int64(offIn)
	signedOffOut := int64(offOut)
	lfIn.withFd(func(fdIn int) syscall.Errno {
		return lfOut.withFd(func(fdOut int) syscall.Errno {
			count, errno = doCopyFileRange(fdIn, signedOffIn, fdOut, signedOffOut, int(len), int(flags))
			return OK
		})
	})
	return count, errno
}

// NewLoopbackRoot returns a root node for a loopback file system whose
// root is at the given root. This node implements all NodeXxxxer
// operations available.
func NewLoopbackRoot(rootPath string) (InodeEmbedder, error) {
	var st syscall.Stat_t
	err := syscall.Stat(rootPath, &st)
	if err != nil {
		return nil, err
	}

	// Canonicalize once: securePath containment checks compare against this.
	resolved, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		return nil, err
	}

	root := &LoopbackRoot{
		Path:   resolved,
		Dev:    uint64(st.Dev),
		RootFD: -1,
	}

	rootNode := root.newNode(nil, "", &st)
	root.RootNode = rootNode
	return rootNode, nil
}

// NewLoopbackRootFD returns a loopback root addressed through an already
// pinned directory descriptor (/proc/self/fd on Linux, /dev/fd on Darwin).
// Path-based operations still resolve through securePath, while renaming or
// replacing the original host directory no longer retargets the export.
// rootFD must remain open for the export's lifetime.
func NewLoopbackRootFD(rootPath string, rootFD int) (InodeEmbedder, error) {
	resolved, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		// A confined worker (docs/worker-confinement.md) has NO path
		// access: EPERM under Seatbelt, ENOENT in the empty mount root.
		// Identity comes from the pinned descriptor either way, so
		// derive the canonical path from the fd (F_GETPATH on darwin)
		// and fall back to the raw path — for pinned roots RootPrefix
		// is display-only (the escape re-resolution in securePath is
		// gated on RootFD < 0).
		resolved = loopbackRootFDPath(rootFD, rootPath)
	}
	fdPath := filepath.Join("/proc/self/fd", fmt.Sprint(rootFD))
	if runtime.GOOS == "darwin" {
		fdPath = filepath.Join("/dev/fd", fmt.Sprint(rootFD))
	}
	// Identity comes from the pinned descriptor, not the path: re-resolving
	// and stating rootPath after the fd was opened would race a host-side
	// swap of the directory.
	var st syscall.Stat_t
	if err := syscall.Fstat(rootFD, &st); err != nil {
		return nil, err
	}
	configuredPath := fdPath
	if runtime.GOOS == "darwin" {
		// Operations resolve F_GETPATH dynamically; Path is only the fallback
		// used if that unexpectedly fails.
		configuredPath = resolved
	}
	root := &LoopbackRoot{Path: configuredPath, RootPrefix: resolved, RootFD: rootFD, Dev: uint64(st.Dev)}
	rootNode := root.newNode(nil, "", &st)
	root.RootNode = rootNode
	return rootNode, nil
}
