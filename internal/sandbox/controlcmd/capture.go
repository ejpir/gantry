package controlcmd

import (
	"fmt"

	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
)

// CapturePackets reads a bounded packet-capture snapshot from a running
// sandbox's daemon.
func CapturePackets(name string, request packetcapture.Request) (packetcapture.Snapshot, error) {
	response, err := controlproto.Call[controlproto.CaptureResponse](name, controlproto.Request{
		Op: "capture.read", ID: controlproto.NewRequestID("capture"), Capture: &request,
	})
	if err != nil {
		return packetcapture.Snapshot{}, err
	}
	if response.Error != "" {
		return packetcapture.Snapshot{}, fmt.Errorf("%s", response.Error)
	}
	return response.Snapshot, nil
}
