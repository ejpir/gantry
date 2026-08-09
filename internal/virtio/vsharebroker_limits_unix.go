//go:build linux || darwin

package virtio

import "golang.org/x/sys/unix"

// shareBrokerHandleLimit preserves at least one quarter of the supervisor's
// descriptor budget (and never less than 64 descriptors) for its control,
// network, log, and lifecycle channels. A generous ceiling keeps one sandbox
// from retaining thousands of share handles even on hosts with huge limits.
func shareBrokerHandleLimit() int {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil || lim.Cur == 0 {
		return 128
	}
	reserve := lim.Cur / 4
	if reserve < 64 {
		reserve = 64
	}
	var allowed uint64
	if lim.Cur > reserve {
		allowed = lim.Cur - reserve
	} else {
		allowed = lim.Cur / 2
	}
	if allowed > 4096 {
		allowed = 4096
	}
	if allowed == 0 {
		allowed = 1
	}
	return int(allowed)
}
