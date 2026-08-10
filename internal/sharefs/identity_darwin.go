//go:build darwin

package sharefs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

func identityFromRoot(root *os.File, info os.FileInfo) (Identity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Identity{}, fmt.Errorf("stat share root: unexpected metadata %T", info.Sys())
	}
	// Darwin's F_GETPATH ABI requires a MAXPATHLEN (1024-byte) buffer.
	var buf [1024]byte
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, root.Fd(), syscall.F_GETPATH, uintptr(unsafe.Pointer(&buf[0])))
	runtime.KeepAlive(root)
	if errno != 0 {
		return Identity{}, fmt.Errorf("resolve pinned share root: %w", errno)
	}
	end := bytes.IndexByte(buf[:], 0)
	if end <= 0 {
		return Identity{}, fmt.Errorf("resolve pinned share root: empty path")
	}
	path := string(buf[:end])
	if !filepath.IsAbs(path) {
		return Identity{}, fmt.Errorf("resolve pinned share root: unusable path %q", path)
	}
	return newIdentity(path, uint64(stat.Dev), stat.Ino, false), nil
}

func identifyRoot(path string) (Identity, error) {
	root, identity, err := openRoot(path)
	if root != nil {
		_ = root.Close()
	}
	return identity, err
}
