//go:build !windows

package policyfeed

import (
	"fmt"
	"os"
	"syscall"
)

func validatePrivateFile(path string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is accessible by group or other users; fix with: chmod 600 %s", path, path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is not owned by the current user", path)
	}
	return nil
}
