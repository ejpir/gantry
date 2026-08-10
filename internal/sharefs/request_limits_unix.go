//go:build linux || darwin

package sharefs

import "golang.org/x/sys/unix"

// shareHandleLimit preserves at least one quarter of the daemon descriptor
// budget (and never less than 64 descriptors) for control, network, logs, and
// lifecycle channels. The absolute ceiling prevents one sandbox from
// retaining thousands of handles on hosts with unusually high limits.
func shareHandleLimit() int {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil || limit.Cur == 0 {
		return 128
	}
	reserve := max(limit.Cur/4, 64)
	allowed := limit.Cur / 2
	if limit.Cur > reserve {
		allowed = limit.Cur - reserve
	}
	return int(min(max(allowed, 1), 4096))
}
