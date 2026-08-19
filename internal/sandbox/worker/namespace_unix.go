//go:build linux || darwin

package worker

import (
	"errors"
	"syscall"
)

// isNamespaceUnavailable reports failures that mean the requested namespace
// tier cannot be created on this host. Besides policy denials, Linux can
// return ENOSPC or EUSERS when user/PID namespace quotas are exhausted. Auto
// mode may honestly degrade around those host constraints; required mode
// still fails closed. EINVAL is intentionally excluded because it can also
// identify malformed spawn attributes rather than an unavailable facility.
func IsNamespaceUnavailable(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EUSERS)
}
