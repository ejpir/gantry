//go:build !linux && !darwin && !windows

package sandbox

// Split-VMM is not available on this platform (no unix socketpairs, no
// SCM_RIGHTS): the VMM stays in the supervisor process.

import (
	"fmt"
	"net"
	"os"

	"github.com/ejpir/gantry/internal/vmm"
)

// vmmWorkerPlatform: re-exec'd VMM workers are NOT supported here.
const vmmWorkerPlatform = false

var errVMMSplitUnavailable = fmt.Errorf("split VMM unavailable on this platform/topology")

func crossProcNetConn() (sup, dev net.Conn, err error) {
	return nil, nil, errVMMSplitUnavailable
}

func tryStartVMMSplit(cfg RunConfig, opts vmm.Opts, nw *Network, shareManager *ShareManager, dir string, console *os.File) (vmmRunner, error) {
	return nil, errVMMSplitUnavailable
}
