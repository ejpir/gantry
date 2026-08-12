package workerconf

import (
	"errors"

	"golang.org/x/sys/windows"
)

// probeReadPath is the canonical "read a user-visible host file" probe
// target for Verify.
const probeReadPath = `C:\Windows\system.ini`

func isConnectionRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED)
}
