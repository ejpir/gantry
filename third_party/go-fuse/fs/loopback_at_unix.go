//go:build linux || darwin

package fs

// Pinned-root relative operations.
//
// When an export is created with a pinned root descriptor (RootFD >= 0),
// every host operation below runs relative to that descriptor via *at
// syscalls instead of the FD -> pathname -> resolve -> pathname-op round
// trip. A concurrent host-side rename or symlink swap can no longer
// retarget an operation between resolution and execution: the walk itself
// is the resolution, every component opens O_NOFOLLOW and must be a real
// directory, and the final *at call acts on the walked descriptor.
//
// Symlinks in the middle of a relative path cannot occur for legitimate
// FUSE traffic (the kernel resolves them via READLINK + fresh LOOKUPs and
// only ever addresses concrete directory inodes), so refusing them during
// the walk breaks no valid guest operation.

import (
	"context"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// statToSyscall converts between the ABI-identical kernel stat structs of
// x/sys/unix and syscall (same layout, different named Timespec fields, so
// a plain Go conversion does not apply).
func statToSyscall(st *unix.Stat_t) syscall.Stat_t {
	return *(*syscall.Stat_t)(unsafe.Pointer(st))
}

// statfsToSyscall is statToSyscall for statfs.
func statfsToSyscall(st *unix.Statfs_t) syscall.Statfs_t {
	return *(*syscall.Statfs_t)(unsafe.Pointer(st))
}

// relJoin joins a node-relative directory and a final component name.
func relJoin(rel, name string) string {
	if rel == "" || rel == "." {
		return name
	}
	return strings.TrimSuffix(rel, "/") + "/" + name
}

// relSplitParent splits a node-relative path into parent directory and
// final component.
func relSplitParent(rel string) (dir, base string) {
	rel = strings.Trim(rel, "/")
	if rel == "" {
		return "", ""
	}
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[:i], rel[i+1:]
	}
	return "", rel
}

// traversalOpenFlags is how the walker opens every intermediate component.
// O_DIRECTORY makes the kernel refuse non-directories AT OPEN TIME: a FIFO
// would otherwise block open(O_RDONLY) until a writer appears, and opening
// a device node has host-side effects — both reachable via crafted guest
// FUSE requests that name a special file as a parent inode. O_NOFOLLOW
// refuses symlink components. The Fstat S_IFDIR check below stays as
// defense in depth.
const traversalOpenFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// openRelDir returns a descriptor for the directory at rel beneath rootFD.
// The returned descriptor has its own open-file description (and therefore
// its own directory offset), including when rel is empty. Every component
// opens with traversalOpenFlags and must stat as a directory: a directory
// swapped for a symlink — or anything else — after lookup fails the walk
// instead of redirecting the operation outside the export. The caller owns
// the returned descriptor.
func openRelDir(rootFD int, rel string) (int, error) {
	// dup(2) would share the root descriptor's directory offset. The first
	// READDIR would then leave the pinned descriptor at EOF, making every
	// later READDIR of the export root appear empty. openat(".") pins the
	// same directory while creating an independent open-file description.
	cur, err := unix.Openat(rootFD, ".", traversalOpenFlags, 0)
	if err != nil {
		return -1, err
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(cur, &rootStat); err != nil || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(cur)
		if err == nil {
			err = unix.ENOTDIR
		}
		return -1, err
	}
	for _, comp := range strings.Split(rel, "/") {
		if comp == "" || comp == "." {
			continue
		}
		next, err := unix.Openat(cur, comp, traversalOpenFlags, 0)
		unix.Close(cur)
		if err != nil {
			return -1, err
		}
		var st unix.Stat_t
		if err := unix.Fstat(next, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			unix.Close(next)
			if err == nil {
				err = unix.ENOTDIR
			}
			return -1, err
		}
		cur = next
	}
	return cur, nil
}

// withParentAt runs fn(dirfd, base) with dirfd pinned to rel's parent
// directory beneath rootFD.
func withParentAt(rootFD int, rel string, fn func(dirfd int, base string) error) syscall.Errno {
	dir, base := relSplitParent(rel)
	dirfd, err := openRelDir(rootFD, dir)
	if err != nil {
		return ToErrno(err)
	}
	defer unix.Close(dirfd)
	return ToErrno(fn(dirfd, base))
}

// lstatRel stats rel (without following a final symlink) relative to
// rootFD; rel "" stats the pinned root itself.
func lstatRel(rootFD int, rel string) (syscall.Stat_t, syscall.Errno) {
	dir, base := relSplitParent(rel)
	dirfd, err := openRelDir(rootFD, dir)
	if err != nil {
		return syscall.Stat_t{}, ToErrno(err)
	}
	defer unix.Close(dirfd)
	var st unix.Stat_t
	if base == "" {
		err = unix.Fstat(dirfd, &st)
	} else {
		err = unix.Fstatat(dirfd, base, &st, unix.AT_SYMLINK_NOFOLLOW)
	}
	if err != nil {
		return syscall.Stat_t{}, ToErrno(err)
	}
	return statToSyscall(&st), 0
}

// pinned reports whether this export operates relative to a pinned root
// descriptor.
func (n *LoopbackNode) pinned() bool { return n.RootData.RootFD >= 0 }

// relPath is the node's path relative to the pinned root, slash-separated.
func (n *LoopbackNode) relPath() string {
	return filepathToSlashTrim(n.relativePath())
}

func filepathToSlashTrim(p string) string {
	return strings.Trim(p, "/")
}

// preserveOwnerAt sets uid/gid of the node at dirfd/base according to the
// caller information in ctx (lchown semantics, as preserveOwner).
func (n *LoopbackNode) preserveOwnerAt(ctx context.Context, dirfd int, base string) {
	if os.Getuid() != 0 {
		return
	}
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		return
	}
	_ = unix.Fchownat(dirfd, base, int(caller.Uid), int(caller.Gid), unix.AT_SYMLINK_NOFOLLOW)
}

// mknodAt is the pinned-root MKNOD (denied by policy layers above, kept
// correct for completeness).
func (n *LoopbackNode) mknodAt(ctx context.Context, name string, mode, rdev uint32, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	rel := relJoin(n.relPath(), name)
	errno := withParentAt(n.RootData.RootFD, rel, func(dirfd int, base string) error {
		if err := mknodatRel(dirfd, base, mode, rdev); err != nil {
			return err
		}
		n.preserveOwnerAt(ctx, dirfd, base)
		return nil
	})
	if errno != 0 {
		return nil, errno
	}
	st, errno := lstatRel(n.RootData.RootFD, rel)
	if errno != 0 {
		_ = withParentAt(n.RootData.RootFD, rel, func(dirfd int, base string) error {
			return unix.Unlinkat(dirfd, base, 0)
		})
		return nil, errno
	}
	out.Attr.FromStat(&st)
	node := n.RootData.newNode(n.EmbeddedInode(), name, &st)
	return n.NewInode(ctx, node, n.RootData.idFromStat(&st)), 0
}

func (n *LoopbackNode) mkdirAt(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	rel := relJoin(n.relPath(), name)
	errno := withParentAt(n.RootData.RootFD, rel, func(dirfd int, base string) error {
		if err := unix.Mkdirat(dirfd, base, mode); err != nil {
			return err
		}
		n.preserveOwnerAt(ctx, dirfd, base)
		return nil
	})
	if errno != 0 {
		return nil, errno
	}
	st, errno := lstatRel(n.RootData.RootFD, rel)
	if errno != 0 {
		_ = withParentAt(n.RootData.RootFD, rel, func(dirfd int, base string) error {
			return unix.Unlinkat(dirfd, base, unix.AT_REMOVEDIR)
		})
		return nil, errno
	}
	out.Attr.FromStat(&st)
	node := n.RootData.newNode(n.EmbeddedInode(), name, &st)
	return n.NewInode(ctx, node, n.RootData.idFromStat(&st)), 0
}

func (n *LoopbackNode) symlinkAt(ctx context.Context, target, name string, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	rel := relJoin(n.relPath(), name)
	errno := withParentAt(n.RootData.RootFD, rel, func(dirfd int, base string) error {
		if err := unix.Symlinkat(target, dirfd, base); err != nil {
			return err
		}
		n.preserveOwnerAt(ctx, dirfd, base)
		return nil
	})
	if errno != 0 {
		return nil, errno
	}
	st, errno := lstatRel(n.RootData.RootFD, rel)
	if errno != 0 {
		_ = withParentAt(n.RootData.RootFD, rel, func(dirfd int, base string) error {
			return unix.Unlinkat(dirfd, base, 0)
		})
		return nil, errno
	}
	out.Attr.FromStat(&st)
	node := n.RootData.newNode(n.EmbeddedInode(), name, &st)
	return n.NewInode(ctx, node, n.RootData.idFromStat(&st)), 0
}

// linkAt hard-links target beneath n as name; both sides pinned. Flags 0
// matches link(2): a symlink target links the link itself.
func (n *LoopbackNode) linkAt(ctx context.Context, target *LoopbackNode, name string, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	newRel := relJoin(n.relPath(), name)
	oldDir, oldBase := relSplitParent(target.relPath())
	newDir, newBase := relSplitParent(newRel)
	oldFd, err := openRelDir(n.RootData.RootFD, oldDir)
	if err != nil {
		return nil, ToErrno(err)
	}
	defer unix.Close(oldFd)
	newFd, err := openRelDir(n.RootData.RootFD, newDir)
	if err != nil {
		return nil, ToErrno(err)
	}
	defer unix.Close(newFd)
	if err := unix.Linkat(oldFd, oldBase, newFd, newBase, 0); err != nil {
		return nil, ToErrno(err)
	}
	st, errno := lstatRel(n.RootData.RootFD, newRel)
	if errno != 0 {
		_ = unix.Unlinkat(newFd, newBase, 0)
		return nil, errno
	}
	out.Attr.FromStat(&st)
	node := n.RootData.newNode(n.EmbeddedInode(), name, &st)
	return n.NewInode(ctx, node, n.RootData.idFromStat(&st)), 0
}

// renameAt is the flags==0 RENAME with both parents pinned to their
// walked descriptors.
func (n *LoopbackNode) renameAt(name string, newParent *LoopbackNode, newName string) syscall.Errno {
	rel1 := relJoin(n.relPath(), name)
	rel2 := relJoin(newParent.relPath(), newName)
	dir1, base1 := relSplitParent(rel1)
	dir2, base2 := relSplitParent(rel2)
	fd1, err := openRelDir(n.RootData.RootFD, dir1)
	if err != nil {
		return ToErrno(err)
	}
	defer unix.Close(fd1)
	fd2, err := openRelDir(n.RootData.RootFD, dir2)
	if err != nil {
		return ToErrno(err)
	}
	defer unix.Close(fd2)
	return ToErrno(unix.Renameat(fd1, base1, fd2, base2))
}

func (n *LoopbackNode) createAt(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*Inode, FileHandle, uint32, syscall.Errno) {
	hostFlags := openFlagsToHost(flags) &^ syscall.O_APPEND
	rel := relJoin(n.relPath(), name)
	fd := -1
	errno := withParentAt(n.RootData.RootFD, rel, func(dirfd int, base string) error {
		var err error
		fd, err = unix.Openat(dirfd, base, hostFlags|unix.O_CREAT|unix.O_NOFOLLOW, uint32(mode))
		if err != nil {
			return err
		}
		n.preserveOwnerAt(ctx, dirfd, base)
		return nil
	})
	if errno != 0 {
		return nil, nil, 0, errno
	}
	var ust unix.Stat_t
	if err := unix.Fstat(fd, &ust); err != nil {
		unix.Close(fd)
		return nil, nil, 0, ToErrno(err)
	}
	st := statToSyscall(&ust)
	node := n.RootData.newNode(n.EmbeddedInode(), name, &st)
	ch := n.NewInode(ctx, node, n.RootData.idFromStat(&st))
	out.FromStat(&st)
	return ch, NewLoopbackFile(fd), 0, 0
}

// setattrAt is the pinned-root SETATTR: every mutation relative to the
// walked parent descriptor, mirroring the pathname variant's semantics
// (lchown, utimens-no-follow, truncate before times).
func (n *LoopbackNode) setattrAt(ctx context.Context, f FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	fsa, ok := f.(FileSetattrer)
	if ok && fsa != nil {
		if errno := fsa.Setattr(ctx, in, out); errno != 0 {
			return errno
		}
	} else {
		rel := n.relPath()
		dir, base := relSplitParent(rel)
		dirfd, err := openRelDir(n.RootData.RootFD, dir)
		if err != nil {
			return ToErrno(err)
		}
		defer unix.Close(dirfd)
		target := base
		if target == "" {
			target = "." // the export root itself
		}

		if m, ok := in.GetMode(); ok {
			if base == "" {
				err = unix.Fchmod(dirfd, m)
			} else {
				err = unix.Fchmodat(dirfd, base, m, 0)
			}
			if err != nil {
				return ToErrno(err)
			}
		}

		uid, uok := in.GetUID()
		gid, gok := in.GetGID()
		if uok || gok {
			suid, sgid := -1, -1
			if uok {
				suid = int(uid)
			}
			if gok {
				sgid = int(gid)
			}
			if err := unix.Fchownat(dirfd, target, suid, sgid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return ToErrno(err)
			}
		}

		// Truncate before setting times, so an explicit mtime is not
		// clobbered by the truncate.
		if sz, ok := in.GetSize(); ok {
			fd, err := unix.Openat(dirfd, base, unix.O_WRONLY|unix.O_NOFOLLOW, 0)
			if err != nil {
				return ToErrno(err)
			}
			err = unix.Ftruncate(fd, int64(sz))
			unix.Close(fd)
			if err != nil {
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
			if err := unix.UtimesNanoAt(dirfd, target, ts, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return ToErrno(err)
			}
		}
	}

	fga, ok := f.(FileGetattrer)
	if ok && fga != nil {
		fga.Getattr(ctx, out)
	} else {
		st, errno := lstatRel(n.RootData.RootFD, n.relPath())
		if errno != 0 {
			return errno
		}
		out.FromStat(&st)
	}
	return OK
}
