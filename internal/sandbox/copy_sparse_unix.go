//go:build linux || darwin

package sandbox

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// copySparse clones a (typically sparse) disk image preserving holes via
// SEEK_HOLE/SEEK_DATA.
func copySparse(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	off := int64(0)
	size := fi.Size()
	for off < size {
		data, err := unix.Seek(int(in.Fd()), off, unix.SEEK_DATA)
		if err == unix.ENXIO {
			break // trailing hole to end of file
		}
		if err != nil { // filesystem without SEEK_HOLE: full copy
			if _, err := in.Seek(0, io.SeekStart); err != nil {
				out.Close()
				return err
			}
			if _, err := io.Copy(out, in); err != nil {
				out.Close()
				return err
			}
			return out.Close()
		}
		hole, err := unix.Seek(int(in.Fd()), data, unix.SEEK_HOLE)
		if err != nil {
			out.Close()
			return err
		}
		if _, err := in.Seek(data, io.SeekStart); err != nil {
			out.Close()
			return err
		}
		if _, err := io.CopyN(out, in, hole-data); err != nil {
			out.Close()
			return err
		}
		off = hole
	}
	if err := out.Truncate(size); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
