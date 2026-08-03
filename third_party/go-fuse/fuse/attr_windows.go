//go:build windows

// GANTRY PATCH: os.FileInfo on Windows cannot provide syscall.Stat_t. The
// native passthrough backend fills Attr directly from Windows metadata.
package fuse

import (
	"os"
	"time"
)

func (a *Attr) IsFifo() bool          { return a.Mode&S_IFMT == S_IFIFO }
func (a *Attr) IsChar() bool          { return false }
func (a *Attr) IsDir() bool           { return a.Mode&S_IFMT == S_IFDIR }
func (a *Attr) IsBlock() bool         { return false }
func (a *Attr) IsRegular() bool       { return a.Mode&S_IFMT == S_IFREG }
func (a *Attr) IsSymlink() bool       { return a.Mode&S_IFMT == S_IFLNK }
func (a *Attr) IsSocket() bool        { return false }
func (a *Attr) ChangeTime() time.Time { return time.Unix(int64(a.Ctime), int64(a.Ctimensec)) }
func (a *Attr) AccessTime() time.Time { return time.Unix(int64(a.Atime), int64(a.Atimensec)) }
func (a *Attr) ModTime() time.Time    { return time.Unix(int64(a.Mtime), int64(a.Mtimensec)) }

func (a *Attr) SetTimes(access *time.Time, mod *time.Time, chstatus *time.Time) {
	if access != nil {
		a.Atime = uint64(access.Unix())
		a.Atimensec = uint32(access.Nanosecond())
	}
	if mod != nil {
		a.Mtime = uint64(mod.Unix())
		a.Mtimensec = uint32(mod.Nanosecond())
	}
	if chstatus != nil {
		a.Ctime = uint64(chstatus.Unix())
		a.Ctimensec = uint32(chstatus.Nanosecond())
	}
}

func ToStatT(f os.FileInfo) any  { return nil }
func ToAttr(f os.FileInfo) *Attr { return nil }
