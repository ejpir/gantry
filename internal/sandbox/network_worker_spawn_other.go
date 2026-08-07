//go:build !linux && !darwin

package sandbox

import (
	"fmt"
	"net"
	"os"
)

// Split network workers are implemented for Unix socketpairs first
// (docs/vmm-network-isolation.md Phase 1); Windows named-pipe handle
// inheritance lands with its platform confinement spike (Phase 5).
func spawnNetWorkerProcess(stderrPath string) (control, data net.Conn, cmd *os.Process, err error) {
	_ = stderrPath
	return nil, nil, nil, fmt.Errorf("split network worker unavailable on this platform")
}

func inheritedConn(fd uintptr, name string) (net.Conn, error) {
	return nil, fmt.Errorf("inherited worker channels unavailable on this platform")
}
