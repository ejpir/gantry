package controlproto

import "github.com/ejpir/gantry/internal/packetcapture"

type CaptureResponse struct {
	packetcapture.Snapshot
	Error string `json:"error,omitempty"`
}
