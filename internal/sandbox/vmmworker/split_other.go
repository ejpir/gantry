//go:build !linux && !darwin && !windows

package vmmworker

// Split-VMM is not available on this platform (no unix socketpairs, no
// SCM_RIGHTS): the VMM stays in the supervisor process.

import (
	"fmt"
	"net"
	"os"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/vmm"
)

// Supported: re-exec'd VMM workers are NOT supported here.
const Supported = false

var ErrUnavailable = fmt.Errorf("split VMM unavailable on this platform/topology")

func CrossProcNetConn() (sup, dev net.Conn, err error) {
	return nil, nil, ErrUnavailable
}

func TryStart(cfg config.RunConfig, opts vmm.Opts, nw *NetAttachment, shareManager *control.ShareManager, dir string, console *os.File) (Runner, error) {
	return nil, ErrUnavailable
}
