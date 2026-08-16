package sandbox

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/ejpir/gantry/internal/packetcapture"
)

type packetCaptureBackend interface {
	Capture(packetcapture.Request) (packetcapture.Snapshot, error)
}

func packetCaptureBackendFor(network *Network, runner vmmRunner) packetCaptureBackend {
	if network == nil {
		return nil
	}
	if network.Worker != nil {
		return network.Worker
	}
	// When the VMM is split but the netstack is local/external, virtio-net and
	// its TrafficRecorder live in the VMM worker. In monolithic mode the
	// supervisor-owned recorder is the packet boundary.
	if worker, ok := runner.(packetCaptureBackend); ok {
		return worker
	}
	if network.Traffic != nil {
		return network.Traffic
	}
	return nil
}

type brokerCaptureResponse struct {
	packetcapture.Snapshot
	Error string `json:"error,omitempty"`
}

func (br *broker) captureControl(conn net.Conn, request brokerRequest) {
	respond := func(response brokerCaptureResponse) { _ = json.NewEncoder(conn).Encode(&response) }
	if br.capture == nil {
		respond(brokerCaptureResponse{Error: "packet capture unavailable"})
		return
	}
	if request.Capture == nil {
		respond(brokerCaptureResponse{Error: "capture request is required"})
		return
	}
	snapshot, err := br.capture.Capture(*request.Capture)
	if err != nil {
		respond(brokerCaptureResponse{Error: fmt.Sprintf("capture: %v", err)})
		return
	}
	respond(brokerCaptureResponse{Snapshot: snapshot})
}

func captureSandboxPackets(name string, request packetcapture.Request) (packetcapture.Snapshot, error) {
	response, err := callControl[brokerCaptureResponse](name, brokerRequest{
		Op: "capture.read", ID: newControlRequestID("capture"), Capture: &request,
	})
	if err != nil {
		return packetcapture.Snapshot{}, err
	}
	if response.Error != "" {
		return packetcapture.Snapshot{}, fmt.Errorf("%s", response.Error)
	}
	return response.Snapshot, nil
}
