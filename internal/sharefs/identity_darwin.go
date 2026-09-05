//go:build darwin

package sharefs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	var statfs syscall.Statfs_t
	if err := syscall.Fstatfs(int(root.Fd()), &statfs); err != nil {
		return Identity{}, fmt.Errorf("statfs pinned share root: %w", err)
	}
	volume := uint64(uint32(statfs.Fsid.Val[0]))<<32 | uint64(uint32(statfs.Fsid.Val[1]))
	identity := newIdentity(path, volume, stat.Ino, true)
	identity.filesystem = darwinInt8String(statfs.Fstypename[:])

	// APFS firmlinks make Data-volume objects visible at namespace paths such
	// as /Users even though that volume is mounted at /System/Volumes/Data.
	// Compare a volume-local scope, keyed by f_fsid rather than st_dev (sealed
	// System and Data volumes may report the same st_dev). F_GETPATH already
	// returns the firmlink spelling for descendants; the mount root itself is
	// normalized to "/" so it directionally contains those descendants.
	mountPoint := filepath.Clean(darwinInt8String(statfs.Mntonname[:]))
	identity.scope = filepath.Clean(path)
	if mountPoint != "" {
		switch {
		case identity.scope == mountPoint:
			identity.scope = string(filepath.Separator)
		case strings.HasPrefix(identity.scope, mountPoint+string(filepath.Separator)):
			identity.scope = strings.TrimPrefix(identity.scope, mountPoint)
		}
	}
	identity.scopeValid = filepath.IsAbs(identity.scope)
	return identity, nil
}

func darwinInt8String(raw []int8) string {
	buf := make([]byte, 0, len(raw))
	for _, c := range raw {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}

func identifyRoot(path string) (Identity, error) {
	root, identity, err := openRoot(path)
	if root != nil {
		_ = root.Close()
	}
	return identity, err
}
