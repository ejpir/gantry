//go:build !windows

package atomicfile

// CanMakeDurableAfterCommit reports whether MakeDurable provides the same
// successful-return guarantee as this platform's durable atomic replacement.
func CanMakeDurableAfterCommit() bool { return true }
