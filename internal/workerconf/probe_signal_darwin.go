//go:build darwin

package workerconf

import (
	"os"
	"syscall"
)

// probeProcSignal verifies that Seatbelt still permits the Go runtime's
// self-signaling while denying a non-delivering signal check against the
// live supervisor parent.
func probeProcSignal(noProcX bool) PropertyResult {
	return evaluateProcSignalProbe(noProcX, os.Getpid(), os.Getppid(), func(pid int) error {
		return syscall.Kill(pid, syscall.Signal(0))
	})
}
