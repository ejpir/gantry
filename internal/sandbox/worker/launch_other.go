//go:build !linux && !darwin && !windows

package worker

import (
	"fmt"
	"net"
	"os"
)

func launchPlatformProcess(_ string, _, _ []string, spec LaunchSpec,
	_ *os.File) (*os.Process, map[string]net.Conn, Containment, error) {
	return nil, nil, nil, fmt.Errorf("split %s worker unavailable on this platform", spec.Role)
}
