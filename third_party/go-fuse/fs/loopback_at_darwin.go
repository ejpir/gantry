//go:build darwin

package fs

import "syscall"

// Darwin has no mknodat(2). MKNOD is default-denied by every gantry policy
// layer before it can reach this path, so the pinned-root fallback fails
// closed rather than silently widening to a pathname mknod.
func mknodatRel(dirfd int, base string, mode uint32, rdev uint32) error {
	return syscall.ENOSYS
}
