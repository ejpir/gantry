//go:build linux || darwin

package workerconf

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// SetFileSizeLimit caps growth through every inherited writable descriptor.
// The supervisor supplies the largest writable disk's fixed size. Lowering
// both the soft and hard limits means a compromised child cannot raise the
// ceiling again; the Linux seccomp profile additionally denies setrlimit.
func SetFileSizeLimit(max uint64) error {
	if max == 0 {
		return nil
	}
	var current unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &current); err != nil {
		return fmt.Errorf("get RLIMIT_FSIZE: %w", err)
	}
	if current.Max != unix.RLIM_INFINITY && max > current.Max {
		return fmt.Errorf("requested RLIMIT_FSIZE %d exceeds hard limit %d", max, current.Max)
	}
	limit := &unix.Rlimit{Cur: max, Max: max}
	if err := unix.Setrlimit(unix.RLIMIT_FSIZE, limit); err != nil {
		return fmt.Errorf("set RLIMIT_FSIZE=%d: %w", max, err)
	}
	return nil
}
