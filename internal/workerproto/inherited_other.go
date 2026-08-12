//go:build !linux && !darwin && !windows

package workerproto

import (
	"fmt"
	"net"
)

// InheritedConn reports that Unix descriptor-based worker bootstrap is not
// available on this platform.
func InheritedConn(fd uintptr, name string) (net.Conn, error) {
	return nil, fmt.Errorf("inherited %s fd %d unavailable on this platform", name, fd)
}
