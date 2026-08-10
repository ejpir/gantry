package vmm

import "errors"

// ErrGuestReset signals a guest-initiated reboot via the reset ports.
var ErrGuestReset = errors.New("guest requested reset via port 0xcf9/0x64")
