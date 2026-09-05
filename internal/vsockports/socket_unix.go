//go:build unix

package vsockports

import (
	"fmt"
	"os"
)

func validateHostSocket(path string, port uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect host port %d: %w", port, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("host port %d endpoint is not a supervisor-owned socket", port)
	}
	return nil
}
