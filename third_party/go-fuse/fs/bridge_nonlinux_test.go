//go:build !linux

package fs

import (
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestAttrToStatx(t *testing.T) {
	attr := fuse.Attr{
		Ino:       42,
		Size:      123,
		Blocks:    8,
		Atime:     10,
		Mtime:     20,
		Ctime:     30,
		Atimensec: 1,
		Mtimensec: 2,
		Ctimensec: 3,
		Mode:      0o100640,
		Nlink:     2,
		Owner:     fuse.Owner{Uid: 1000, Gid: 1001},
		Blksize:   4096,
	}
	var got fuse.Statx
	attrToStatx(&attr, &got)

	if got.Mask != statxBasicStats || got.Ino != attr.Ino || got.Size != attr.Size ||
		got.Mode != uint16(attr.Mode) || got.Uid != attr.Uid || got.Gid != attr.Gid ||
		got.Atime.Sec != attr.Atime || got.Mtime.Nsec != attr.Mtimensec || got.Ctime.Nsec != attr.Ctimensec {
		t.Fatalf("unexpected statx conversion: %+v", got)
	}
}
