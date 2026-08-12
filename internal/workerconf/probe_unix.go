//go:build linux || darwin

package workerconf

import (
	"errors"
	"syscall"
)

// probeReadPath is the canonical "read a user-visible host file" probe
// target for Verify.
const probeReadPath = "/etc/passwd"

func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
