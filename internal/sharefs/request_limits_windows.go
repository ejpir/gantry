//go:build windows

package sharefs

// Windows handles are not governed by RLIMIT_NOFILE. Use the same absolute
// ceiling applied on high-limit Unix hosts.
func shareHandleLimit() int { return 4096 }
