//go:build !windows

package manager

import (
	"fmt"
	"os"
)

func checkPrivateEnrollmentKey(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("unexpected key mode %v", info.Mode())
	}
	return nil
}
