//go:build windows

package atomicfile

// Windows durable replacement relies on MOVEFILE_WRITE_THROUGH at rename time;
// syncing a separately reopened file is not an equivalent guarantee.
func CanMakeDurableAfterCommit() bool { return false }
