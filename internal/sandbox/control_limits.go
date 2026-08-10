package sandbox

import "sync"

const (
	// Each interactive exec uses two control connections: a parked exit-event
	// channel and a streaming stdio channel. Leave ample headroom for short
	// management requests even when the streaming limit is full.
	controlMaxConnections    = 128
	controlMaxParkedSessions = 32
	controlMaxSessions       = 32
)

// brokerLimits contains non-blocking semaphores. Full limits reject new work
// immediately instead of accumulating goroutines behind a slow guest or a
// client that never finishes its handshake.
type brokerLimits struct {
	once        sync.Once
	connections chan struct{}
	parked      chan struct{}
	sessions    chan struct{}
}

func (l *brokerLimits) initialize() {
	l.once.Do(func() {
		if l.connections == nil {
			l.connections = make(chan struct{}, controlMaxConnections)
		}
		if l.parked == nil {
			l.parked = make(chan struct{}, controlMaxParkedSessions)
		}
		if l.sessions == nil {
			l.sessions = make(chan struct{}, controlMaxSessions)
		}
	})
}

func tryAcquireSlot(slots chan struct{}) bool {
	select {
	case slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseSlot(slots chan struct{}) { <-slots }

func (l *brokerLimits) acquireConnection() bool {
	l.initialize()
	return tryAcquireSlot(l.connections)
}

func (l *brokerLimits) releaseConnection() { releaseSlot(l.connections) }

func (l *brokerLimits) acquireParked() bool {
	l.initialize()
	return tryAcquireSlot(l.parked)
}

func (l *brokerLimits) releaseParked() { releaseSlot(l.parked) }

func (l *brokerLimits) acquireSession() bool {
	l.initialize()
	return tryAcquireSlot(l.sessions)
}

func (l *brokerLimits) releaseSession() { releaseSlot(l.sessions) }
