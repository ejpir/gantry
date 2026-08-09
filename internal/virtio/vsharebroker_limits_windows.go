//go:build windows

package virtio

// Windows handles are not governed by RLIMIT_NOFILE. Keep the same absolute
// ceiling used on high-limit Unix hosts so retained broker state is bounded.
func shareBrokerHandleLimit() int { return 4096 }
