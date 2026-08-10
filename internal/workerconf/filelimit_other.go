//go:build !linux && !darwin

package workerconf

import (
	"fmt"
	"runtime"
)

func SetFileSizeLimit(max uint64) error {
	if max == 0 {
		return nil
	}
	return fmt.Errorf("RLIMIT_FSIZE unavailable on %s", runtime.GOOS)
}
