package sandbox

import "github.com/ejpir/gantry/internal/packetcapture"

func (dashboardService) CapturePackets(name string, request packetcapture.Request) (packetcapture.Snapshot, error) {
	if err := ValidateSandboxName(name); err != nil {
		return packetcapture.Snapshot{}, err
	}
	return captureSandboxPackets(name, request)
}
