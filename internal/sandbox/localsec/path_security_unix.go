//go:build !windows

package localsec

import (
	"fmt"
	"os"
	"syscall"
)

func CreateDir(path string) error {
	return os.MkdirAll(path, 0o700)
}

func CreateManagerDir(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%q is not a real directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%q is not owned by the current user", path)
	}
	return os.Chmod(path, 0o700)
}

func SecureDir(path string) error {
	return os.Chmod(path, 0o700)
}

func SecureEndpoint(path string) error {
	return os.Chmod(path, 0o600)
}
