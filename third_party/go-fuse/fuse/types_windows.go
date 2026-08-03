//go:build windows

// GANTRY PATCH: Linux protocol extensions used when the host is Windows and
// the virtio-fs peer is Linux.
package fuse

const (
	ENODATA = Status(61)
	ENOATTR = ENODATA

	EREMOTEIO = Status(121)

	CAP_NO_OPENDIR_SUPPORT  = (1 << 24)
	CAP_EXPLICIT_INVAL_DATA = (1 << 25)
	CAP_MAP_ALIGNMENT       = (1 << 26)
	CAP_SUBMOUNTS           = (1 << 27)
	CAP_HANDLE_KILLPRIV_V2  = (1 << 28)
	CAP_SETXATTR_EXT        = (1 << 29)
	CAP_INIT_EXT            = (1 << 30)
	CAP_INIT_RESERVED       = (1 << 31)

	CAP_RENAME_SWAP = 0x0
)

func (o *InitOut) setFlags(flags uint64) {
	o.Flags = uint32(flags) | CAP_INIT_EXT
	o.Flags2 = uint32(flags >> 32)
}

func (in *InitIn) supportsRenameSwap() bool { return false }

func ft(tsec uint64, tnsec uint32) float64 {
	return float64(tsec) + float64(tnsec)*1e-9
}
