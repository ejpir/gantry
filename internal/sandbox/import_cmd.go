package sandbox

import (
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/importer"
)

// CmdImport implements `gantry import`. The importer resolves the reference
// stack into a sandbox configuration; starting it from that configuration is
// the daemon lifecycle's job and stays here.
func CmdImport(argv []string) int {
	return importer.Cmd(argv, func(name string, cfg config.RunConfig) int {
		return launchSandbox(name, cfg, nil, true)
	})
}
