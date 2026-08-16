package netpol

import "github.com/ejpir/gantry/internal/packetcapture"

// Capture applies a bounded packet-capture request. Keeping this beside the
// traffic observer makes every network topology use the same packet tap:
// monolithic virtio-net, the split VMM worker, and the split network worker.
func (r *TrafficRecorder) Capture(request packetcapture.Request) (packetcapture.Snapshot, error) {
	if r == nil || r.capture == nil {
		return packetcapture.Snapshot{}, nil
	}
	return r.capture.Apply(request), nil
}
