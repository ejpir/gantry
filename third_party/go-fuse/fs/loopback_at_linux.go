//go:build linux

package fs

import "golang.org/x/sys/unix"

func mknodatRel(dirfd int, base string, mode uint32, rdev uint32) error {
	return unix.Mknodat(dirfd, base, mode, intDev(rdev))
}
