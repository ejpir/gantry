//go:build !darwin

package fs

import "syscall"

func openFlagsToHost(f uint32) int  { return int(f) }
func xattrFlagsToHost(f uint32) int { return int(f) }
func renameFlagsToHost(f uint32) (uint, syscall.Errno) {
	return uint(f), 0
}
