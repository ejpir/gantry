//go:build linux || darwin

package workerconf

import (
	"errors"
	"syscall"
)

// probeReadPath is the canonical "read a user-visible host file" probe
// target for Verify.
const probeReadPath = "/etc/passwd"

func probeFSReadPath() string     { return probeReadPath }
func probeNetDialAddress() string { return "127.0.0.1:1" }

func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

func isConfinementPermission(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}
