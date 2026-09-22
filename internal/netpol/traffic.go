package netpol

// TrafficRecorder coordinates packet observation and optional background
// publication. Those components retain their own mutable state; the recorder
// exposes only lifecycle and observation operations.
type TrafficRecorder struct {
	observer  *trafficObserver
	publisher *trafficPublisher
}

// NewTrafficRecorder starts a recorder at path. A valid previous snapshot is
// resumed so stop/start cycles retain the sandbox's traffic history. An empty
// path creates an in-memory recorder for a confined worker.
func NewTrafficRecorder(path string) *TrafficRecorder {
	store := newTrafficStore(loadTrafficSnapshot(path))
	recorder := &TrafficRecorder{observer: newTrafficObserver(store)}
	persistence := newTrafficPersistence(path, store, writeTrafficSnapshot)
	if persistence != nil {
		// Publish an empty marker immediately. The TUI uses its presence to
		// distinguish "no traffic yet" from a VM started by an older binary.
		store.markDirty()
		persistence.flush()
	}
	recorder.publisher = startTrafficPublisher(persistence)
	return recorder
}

// Close publishes the final snapshot and joins the writer goroutine. Every
// caller joins the same shutdown; the publisher remains the sole owner of its
// ticker and channels.
func (r *TrafficRecorder) Close() {
	if r == nil || r.publisher == nil {
		return
	}
	r.publisher.Close()
}

// BeginEpoch starts accumulation for one remote recorder lifetime. The epoch
// holds only bounded counter watermarks; the destination aggregate owns the
// retained entries and persistence.
func (r *TrafficRecorder) BeginEpoch() *TrafficEpoch {
	if r == nil || r.observer == nil {
		return nil
	}
	return newTrafficEpoch(r.observer.store)
}

// Snapshot returns a stable in-memory copy, primarily for tests and callers
// that live in the VMM process.
func (r *TrafficRecorder) Snapshot() TrafficSnapshot {
	return r.observer.snapshot()
}

// ObserveTX records one frame sent by the guest and its policy decision.
func (r *TrafficRecorder) ObserveTX(frame []byte, allowed bool) {
	if r == nil || r.observer == nil || len(frame) == 0 {
		return
	}
	r.observer.observeTX(frame, allowed)
}

// ObserveRX records one frame delivered to the guest.
func (r *TrafficRecorder) ObserveRX(frame []byte) {
	if r == nil || r.observer == nil || len(frame) == 0 {
		return
	}
	r.observer.observeRX(frame)
}
