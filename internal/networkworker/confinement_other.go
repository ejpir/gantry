//go:build !linux && !darwin && !windows

package networkworker

import (
	"fmt"
	"net"
	"runtime"

	"github.com/ejpir/gantry/internal/workerconf"
)

func ApplyConfinement(config Config, _, _ net.Conn) (*workerconf.Report, error) {
	mode := config.Confinement
	if mode == "" {
		mode = "auto"
	}
	report := workerconf.DisabledReport(runtime.GOOS, mode)
	if mode == "off" {
		return &report, nil
	}
	return &report, fmt.Errorf("network worker: confinement unavailable on %s", runtime.GOOS)
}

func RequiredConfinementProperties(string) []string {
	return []string{
		workerconf.PropFSRead,
		workerconf.PropFSWrite,
		workerconf.PropExec,
		workerconf.PropProcSignal,
	}
}
