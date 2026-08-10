//go:build linux

package sharefs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func identityFromRoot(root *os.File, info os.FileInfo) (Identity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Identity{}, fmt.Errorf("stat share root: unexpected metadata %T", info.Sys())
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", root.Fd()))
	if err != nil {
		return Identity{}, fmt.Errorf("resolve pinned share root: %w", err)
	}
	if !filepath.IsAbs(path) || strings.HasSuffix(path, " (deleted)") {
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
