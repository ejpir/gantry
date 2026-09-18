//go:build linux || darwin || windows

package sharefs

import "github.com/ejpir/gantry/internal/sharefs/exportstate"

type ExportState = exportstate.Phase

const (
	ExportActive   = exportstate.Active
	ExportDraining = exportstate.Draining
	ExportRevoked  = exportstate.Revoked
	ExportGone     = exportstate.Gone
)

func validExportTransition(current, next ExportState) bool {
	return exportstate.ValidTransition(current, next)
}
