//go:build windows

package fuse

import (
	"syscall"
	"testing"
)

// Zero is success everywhere: the fs bridge returns bare syscall.Errno(0)
// from successful node ops (and for negative-cache lookups), which must map
// to OK on the wire. Linux maps identically and Darwin special-cases 0;
// Windows must too, or every successful mutation reports EIO to the guest.
func TestHostErrnoZeroMapsToOK(t *testing.T) {
	if st := hostErrnoToLinux(0); st != OK {
		t.Errorf("hostErrnoToLinux(0) = %v, want OK", st)
	}
	if st := ToStatus(syscall.Errno(0)); st != OK {
		t.Errorf("ToStatus(syscall.Errno(0)) = %v, want OK", st)
	}
	if st := ToStatus(syscall.ENOENT); st != ENOENT {
		t.Errorf("ToStatus(syscall.ENOENT) = %v, want ENOENT", st)
	}
}
