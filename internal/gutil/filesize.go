package gutil

import (
	"errors"
	"io"
	"os"
)

// FileSize returns the size of an open regular file. It prefers fstat but
// falls back to lseek(SEEK_END) when stat is denied: Ubuntu 24.04+ attaches
// a generated AppArmor profile to processes that create an unprivileged
// user namespace, and that profile mediates inode_getattr on inherited
// descriptors whose paths it does not cover (fstat then fails EACCES)
// while leaving read and llseek alone. A confined split-VMM worker must
// size the supervisor-opened kernel, initrd, and disk descriptors it
// inherits without any path-mediated metadata right.
//
// Only permission failures fall back; structural errors (bad descriptor,
// unsized special file) surface unchanged. The shared descriptor offset is
// restored before returning.
func FileSize(f *os.File) (int64, error) {
	fi, statErr := f.Stat()
	if statErr == nil {
		return fi.Size(), nil
	}
	if !errors.Is(statErr, os.ErrPermission) {
		return 0, statErr
	}
	cur, seekErr := f.Seek(0, io.SeekCurrent)
	if seekErr != nil {
		return 0, statErr
	}
	end, seekErr := f.Seek(0, io.SeekEnd)
	if seekErr != nil {
		return 0, statErr
	}
	// Best-effort restore: the descriptor may share its open file
	// description with the supervisor, so leave the offset as found.
	_, _ = f.Seek(cur, io.SeekStart)
	return end, nil
}
