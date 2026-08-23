package workerconf

import (
	"errors"
	"net"
	"os"

	"golang.org/x/sys/windows"
)

// probeReadPath is the canonical "read a user-visible host file" probe
// target for Verify.
const probeReadPath = `C:\Windows\system.ini`

func probeFSReadPath() string {
	if path := os.Getenv("GANTRY_WORKER_PROBE_READ_PATH"); path != "" {
		return path
	}
	return probeReadPath
}

func probeNetDialAddress() string {
	if address := os.Getenv("GANTRY_WORKER_PROBE_NET_ADDR"); address != "" {
		return address
	}
	return "127.0.0.1:1"
}

func isConnectionRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED)
}

func isConfinementPermission(err error) bool {
	if errors.Is(err, windows.WSAEACCES) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return true
	}
	// Windows Network Isolation can silently drop a zero-capability
	// AppContainer's connect instead of returning WSAEACCES. A timeout alone is
	// never proof; combine it with direct token verification that this is an
	// AppContainer and that no network (or other) capabilities were granted.
	networkError, timedOut := err.(net.Error)
	policyTimeout := errors.Is(err, windows.WSAETIMEDOUT) || (timedOut && networkError.Timeout())
	if !policyTimeout {
		return false
	}
	token := windows.GetCurrentProcessToken()
	appContainer, appContainerErr := tokenIsAppContainerEnabled(token)
	hasCapabilities, capabilitiesErr := tokenHasCapabilities(token)
	return appContainerErr == nil && capabilitiesErr == nil && appContainer && !hasCapabilities
}
