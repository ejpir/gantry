//go:build !linux && !darwin && !windows

package networker

import (
	"fmt"
	"net"
	"os"

	"github.com/ejpir/gantry/internal/sandbox/boundedlog"
)

// Split network workers are implemented for Unix socketpairs first
// (docs/vmm-network-isolation.md Phase 1); Windows named-pipe handle
// inheritance lands with its platform confinement spike (Phase 5).
func spawnNetWorkerProcess(stderrPath, confinement string) (control, data net.Conn, cmd *os.Process, diagnostics *boundedlog.Pipe, err error) {
	_, _ = stderrPath, confinement
	return nil, nil, nil, nil, fmt.Errorf("split network worker unavailable on this platform")
}
