//go:build !windows

package remote

import (
	"fmt"
	"os"

	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

func secureTokenFile(path string) error {
	if err := localsec.SecureRegularFile(path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func validateTokenFileSecurity(path string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("token file %s is accessible by other users (%04o); fix with: chmod 600 %s", path, info.Mode().Perm(), path)
	}
	return nil
}
