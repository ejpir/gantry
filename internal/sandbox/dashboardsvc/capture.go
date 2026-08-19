package dashboardsvc

import (
	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/ejpir/gantry/internal/sandbox/controlcmd"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func (dashboardService) CapturePackets(name string, request packetcapture.Request) (packetcapture.Snapshot, error) {
	if err := layout.ValidateName(name); err != nil {
		return packetcapture.Snapshot{}, err
	}
	return controlcmd.CapturePackets(name, request)
}
