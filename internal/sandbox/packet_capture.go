package sandbox

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/vmmworker"
)

type packetCaptureBackend interface {
	Capture(packetcapture.Request) (packetcapture.Snapshot, error)
}

func packetCaptureBackendFor(network *Network, runner vmmworker.Runner) packetCaptureBackend {
	if network == nil {
		return nil
	}
	if network.Worker != nil {
		return network.Worker
	}
	// When the VMM is split but the netstack is local/external, virtio-net and
	// its TrafficRecorder live in the VMM worker. In monolithic mode the
	// supervisor-owned recorder is the packet boundary.
	if backend, ok := runner.(packetCaptureBackend); ok {
		return backend
	}
	if network.Traffic != nil {
		return network.Traffic
	}
	return nil
}

func (br *broker) captureControl(conn net.Conn, request controlproto.Request) {
	respond := func(response controlproto.CaptureResponse) { _ = json.NewEncoder(conn).Encode(&response) }
	if br.capture == nil {
		respond(controlproto.CaptureResponse{Error: "packet capture unavailable"})
		return
	}
	if request.Capture == nil {
		respond(controlproto.CaptureResponse{Error: "capture request is required"})
		return
	}
	snapshot, err := br.capture.Capture(*request.Capture)
	if err != nil {
		respond(controlproto.CaptureResponse{Error: fmt.Sprintf("capture: %v", err)})
		return
	}
	respond(controlproto.CaptureResponse{Snapshot: snapshot})
}
