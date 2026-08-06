//go:build !linux

package fs

import "github.com/hanwen/go-fuse/v2/fuse"

func (b *rawBridge) Statx(cancel <-chan struct{}, in *fuse.StatxIn, out *fuse.StatxOut) fuse.Status {
	// A Linux virtio-fs guest can issue STATX even when the server runs on a
	// host without statx(2), notably macOS. Serve the fields available from
	// ordinary GETATTR instead of rejecting the Linux wire operation.
	getattrIn := fuse.GetAttrIn{
		InHeader: in.InHeader,
		Flags_:   in.GetattrFlags,
		Fh_:      in.Fh,
	}
	var getattrOut fuse.AttrOut
	if status := b.GetAttr(cancel, &getattrIn, &getattrOut); status != fuse.OK {
		return status
	}

	out.SetTimeout(getattrOut.Timeout())
	attrToStatx(&getattrOut.Attr, &out.Statx)
	return fuse.OK
}

// Linux's STATX_BASIC_STATS mask. Birth time and newer Linux-only fields are
// deliberately omitted because a portable Attr cannot represent them.
const statxBasicStats = uint32(0x07ff)

func attrToStatx(attr *fuse.Attr, out *fuse.Statx) {
	*out = fuse.Statx{
		Mask:    statxBasicStats,
		Blksize: attr.Blksize,
		Nlink:   attr.Nlink,
		Uid:     attr.Uid,
		Gid:     attr.Gid,
		Mode:    uint16(attr.Mode),
		Ino:     attr.Ino,
		Size:    attr.Size,
		Blocks:  attr.Blocks,
		Atime:   fuse.SxTime{Sec: attr.Atime, Nsec: attr.Atimensec},
		Ctime:   fuse.SxTime{Sec: attr.Ctime, Nsec: attr.Ctimensec},
		Mtime:   fuse.SxTime{Sec: attr.Mtime, Nsec: attr.Mtimensec},
	}
}
