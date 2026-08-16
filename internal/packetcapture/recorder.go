// Package packetcapture records a bounded, memory-only view of virtual
// Ethernet frames. It deliberately has no host-interface capture support:
// Gantry feeds it frames at the virtio/net-policy boundary, so it works
// without libpcap or elevated host privileges.
package packetcapture

import (
	"sync"
	"time"
)

type Direction string

const (
	TX Direction = "tx"
	RX Direction = "rx"
)

const (
	DefaultMaxPackets = 2048
	DefaultMaxBytes   = 2 << 20
	DefaultSnapLen    = 4 << 10
	MaxReadPackets    = 256
	MaxReadBytes      = 256 << 10
)

// Packet is one captured Ethernet frame. Data is truncated to the recorder's
// snap length; Length always contains the original frame length.
type Packet struct {
	Sequence  uint64    `json:"sequence"`
	Timestamp time.Time `json:"timestamp"`
	Direction Direction `json:"direction"`
	Allowed   bool      `json:"allowed"`
	Length    int       `json:"length"`
	Data      []byte    `json:"data"`
}

// Request is shared by the local recorder and worker/control RPCs. Start is
// idempotent. Clear discards retained frames without disabling capture. Stop
// disables capture and clears payloads so leaving data behind is explicit.
type Request struct {
	Start      bool   `json:"start,omitempty"`
	Clear      bool   `json:"clear,omitempty"`
	Stop       bool   `json:"stop,omitempty"`
	After      uint64 `json:"after,omitempty"`
	MaxPackets int    `json:"max_packets,omitempty"`
	MaxBytes   int    `json:"max_bytes,omitempty"`
}

type Snapshot struct {
	Active  bool     `json:"active"`
	Packets []Packet `json:"packets,omitempty"`
	Next    uint64   `json:"next,omitempty"`   // last sequence returned
	Latest  uint64   `json:"latest,omitempty"` // newest sequence retained/seen
	Oldest  uint64   `json:"oldest,omitempty"`
	Evicted uint64   `json:"evicted,omitempty"`
}

// Recorder is safe on packet-processing and control-plane goroutines. Writes
// never block on disk or a consumer and retain at most maxPackets/maxBytes.
type Recorder struct {
	mu         sync.Mutex
	active     bool
	entries    []Packet
	head       int
	count      int
	bytes      int
	next       uint64
	evicted    uint64
	maxPackets int
	maxBytes   int
	snapLen    int
}

func NewRecorder(maxPackets, maxBytes, snapLen int) *Recorder {
	if maxPackets <= 0 {
		maxPackets = DefaultMaxPackets
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if snapLen <= 0 {
		snapLen = DefaultSnapLen
	}
	return &Recorder{
		entries: make([]Packet, maxPackets), maxPackets: maxPackets,
		maxBytes: maxBytes, snapLen: snapLen,
	}
}

func (r *Recorder) ObserveTX(frame []byte, allowed bool) { r.observe(TX, frame, allowed) }
func (r *Recorder) ObserveRX(frame []byte)               { r.observe(RX, frame, true) }

func (r *Recorder) observe(direction Direction, frame []byte, allowed bool) {
	if r == nil || len(frame) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.active {
		return
	}

	length := min(len(frame), r.snapLen, r.maxBytes)
	data := append([]byte(nil), frame[:length]...)
	for r.count > 0 && (r.count == r.maxPackets || r.bytes+length > r.maxBytes) {
		r.evictLocked()
	}
	if length > r.maxBytes || r.maxPackets == 0 {
		r.evicted++
		return
	}
	r.next++
	index := (r.head + r.count) % len(r.entries)
	r.entries[index] = Packet{
		Sequence: r.next, Timestamp: time.Now(), Direction: direction,
		Allowed: allowed, Length: len(frame), Data: data,
	}
	r.count++
	r.bytes += length
}

func (r *Recorder) evictLocked() {
	packet := &r.entries[r.head]
	r.bytes -= len(packet.Data)
	*packet = Packet{}
	r.head = (r.head + 1) % len(r.entries)
	r.count--
	r.evicted++
}

func (r *Recorder) clearLocked() {
	for r.count > 0 {
		packet := &r.entries[r.head]
		*packet = Packet{}
		r.head = (r.head + 1) % len(r.entries)
		r.count--
	}
	r.head = 0
	r.bytes = 0
}

// Apply updates capture state and returns frames newer than Request.After.
// Read limits are clamped so an untrusted worker can never make a single
// supervisor/control response grow without bound.
func (r *Recorder) Apply(request Request) Snapshot {
	if r == nil {
		return Snapshot{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if request.Stop {
		r.active = false
		r.clearLocked()
		r.evicted = 0
	}
	if request.Clear {
		r.clearLocked()
		r.evicted = 0
	}
	if request.Start {
		r.active = true
	}

	maxPackets := request.MaxPackets
	if maxPackets <= 0 || maxPackets > MaxReadPackets {
		maxPackets = MaxReadPackets
	}
	maxBytes := request.MaxBytes
	if maxBytes <= 0 || maxBytes > MaxReadBytes {
		maxBytes = MaxReadBytes
	}
	snapshot := Snapshot{Active: r.active, Next: request.After, Latest: r.next, Evicted: r.evicted}
	if r.count > 0 {
		snapshot.Oldest = r.entries[r.head].Sequence
	}
	bytes := 0
	for offset := 0; offset < r.count && len(snapshot.Packets) < maxPackets; offset++ {
		packet := r.entries[(r.head+offset)%len(r.entries)]
		if packet.Sequence <= request.After {
			continue
		}
		if len(snapshot.Packets) > 0 && bytes+len(packet.Data) > maxBytes {
			break
		}
		packet.Data = append([]byte(nil), packet.Data...)
		snapshot.Packets = append(snapshot.Packets, packet)
		snapshot.Next = packet.Sequence
		bytes += len(packet.Data)
	}
	return snapshot
}
