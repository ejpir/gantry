package netpol

import (
	"time"

	"github.com/ejpir/gantry/internal/packetcapture"
)

// trafficObserver owns packet admission into both the aggregate and the
// optional capture tap. The facade cannot update one without updating the
// other, while persistence receives only the aggregate it needs.
type trafficObserver struct {
	store   *trafficStore
	capture *packetcapture.Recorder
}

func newTrafficObserver(store *trafficStore) *trafficObserver {
	return &trafficObserver{
		store:   store,
		capture: packetcapture.NewRecorder(0, 0, 0),
	}
}

func (o *trafficObserver) observeTX(frame []byte, allowed bool) {
	o.capture.ObserveTX(frame, allowed)
	o.store.observeTX(frame, allowed, time.Now())
}

func (o *trafficObserver) observeRX(frame []byte) {
	o.capture.ObserveRX(frame)
	o.store.observeRX(frame, time.Now())
}

func (o *trafficObserver) snapshot() TrafficSnapshot {
	return o.store.snapshotAt(time.Now())
}

func (o *trafficObserver) applyCapture(request packetcapture.Request) packetcapture.Snapshot {
	return o.capture.Apply(request)
}
