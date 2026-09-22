package netpol

import (
	"math"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// TrafficEpoch merges cumulative snapshots from one remote recorder into a
// lifetime aggregate. A worker reports counters from zero on every boot, while
// the supervisor aggregate survives those boots on disk. Keeping watermarks in
// this trusted, per-worker capability makes repeated periodic and final
// snapshots idempotent without trusting a worker-supplied epoch identifier.
type TrafficEpoch struct {
	store    *trafficStore
	previous trafficCounters
	entries  map[trafficEntryKey]trafficEntryCounters
	mu       sync.Mutex
}

type trafficCounters struct {
	txBytes, rxBytes             uint64
	txPackets, rxPackets         uint64
	droppedBytes, droppedPackets uint64
}

type trafficEntryCounters struct {
	txBytes, rxBytes     uint64
	txPackets, rxPackets uint64
}

type epochEntryUpdate struct {
	remote    remoteTrafficEntry
	watermark trafficEntryCounters
}

func newTrafficEpoch(store *trafficStore) *TrafficEpoch {
	return &TrafficEpoch{
		store:   store,
		entries: make(map[trafficEntryKey]trafficEntryCounters),
	}
}

// Merge advances this epoch to other. Remote snapshots are cumulative within
// an epoch, so only monotonic deltas are added to lifetime totals. Replays and
// stale snapshots add nothing; a new worker gets a new epoch and contributes
// its counters from zero.
func (epoch *TrafficEpoch) Merge(other TrafficSnapshot) {
	if epoch == nil || epoch.store == nil || other.Version != trafficSnapshotVersion {
		return
	}
	epoch.mu.Lock()
	defer epoch.mu.Unlock()

	next := snapshotCounters(other)
	delta := next.delta(epoch.previous)
	epoch.previous = epoch.previous.max(next)

	entries := other.Entries
	if len(entries) > maxTrafficEntries {
		entries = entries[:maxTrafficEntries]
	}
	updates := epoch.prepareEntryUpdates(entries)
	accepted := epoch.store.mergeRemote(delta, remoteUpdates(updates))
	for i := range updates {
		if accepted[i] {
			epoch.entries[updates[i].remote.key] = updates[i].watermark
		}
	}
}

func (epoch *TrafficEpoch) prepareEntryUpdates(entries []TrafficEntry) []epochEntryUpdate {
	updates := make([]epochEntryUpdate, 0, len(entries))
	// A worker should emit unique entry keys. Track provisional values anyway so
	// duplicate keys in an untrusted snapshot remain monotonic and idempotent.
	provisional := make(map[trafficEntryKey]trafficEntryCounters)
	for i := range entries {
		entry := entries[i]
		if !validMergedTrafficEntry(entry) {
			continue
		}
		key := makeTrafficEntryKey(entry.Address, entry.Host, entry.Protocol, entry.Port, entry.Allowed)
		previous, exists := provisional[key]
		if !exists {
			previous = epoch.entries[key]
		}
		next := entryCounters(entry)
		watermark := previous.max(next)
		provisional[key] = watermark
		updates = append(updates, epochEntryUpdate{
			remote: remoteTrafficEntry{
				key:   key,
				entry: entry,
				delta: next.delta(previous),
			},
			watermark: watermark,
		})
	}
	return updates
}

func remoteUpdates(updates []epochEntryUpdate) []remoteTrafficEntry {
	remote := make([]remoteTrafficEntry, len(updates))
	for i := range updates {
		remote[i] = updates[i].remote
	}
	return remote
}

func snapshotCounters(snapshot TrafficSnapshot) trafficCounters {
	return trafficCounters{
		txBytes: snapshot.TXBytes, rxBytes: snapshot.RXBytes,
		txPackets: snapshot.TXPackets, rxPackets: snapshot.RXPackets,
		droppedBytes: snapshot.DroppedBytes, droppedPackets: snapshot.DroppedPackets,
	}
}

func entryCounters(entry TrafficEntry) trafficEntryCounters {
	return trafficEntryCounters{
		txBytes: entry.TXBytes, rxBytes: entry.RXBytes,
		txPackets: entry.TXPackets, rxPackets: entry.RXPackets,
	}
}

func (c trafficCounters) delta(previous trafficCounters) trafficCounters {
	return trafficCounters{
		txBytes:        monotonicDelta(c.txBytes, previous.txBytes),
		rxBytes:        monotonicDelta(c.rxBytes, previous.rxBytes),
		txPackets:      monotonicDelta(c.txPackets, previous.txPackets),
		rxPackets:      monotonicDelta(c.rxPackets, previous.rxPackets),
		droppedBytes:   monotonicDelta(c.droppedBytes, previous.droppedBytes),
		droppedPackets: monotonicDelta(c.droppedPackets, previous.droppedPackets),
	}
}

func (c trafficCounters) max(other trafficCounters) trafficCounters {
	return trafficCounters{
		txBytes: max(c.txBytes, other.txBytes), rxBytes: max(c.rxBytes, other.rxBytes),
		txPackets: max(c.txPackets, other.txPackets), rxPackets: max(c.rxPackets, other.rxPackets),
		droppedBytes:   max(c.droppedBytes, other.droppedBytes),
		droppedPackets: max(c.droppedPackets, other.droppedPackets),
	}
}

func (c trafficCounters) zero() bool {
	return c == (trafficCounters{})
}

func (c trafficEntryCounters) delta(previous trafficEntryCounters) trafficEntryCounters {
	return trafficEntryCounters{
		txBytes:   monotonicDelta(c.txBytes, previous.txBytes),
		rxBytes:   monotonicDelta(c.rxBytes, previous.rxBytes),
		txPackets: monotonicDelta(c.txPackets, previous.txPackets),
		rxPackets: monotonicDelta(c.rxPackets, previous.rxPackets),
	}
}

func (c trafficEntryCounters) max(other trafficEntryCounters) trafficEntryCounters {
	return trafficEntryCounters{
		txBytes: max(c.txBytes, other.txBytes), rxBytes: max(c.rxBytes, other.rxBytes),
		txPackets: max(c.txPackets, other.txPackets), rxPackets: max(c.rxPackets, other.rxPackets),
	}
}

func (c trafficEntryCounters) zero() bool {
	return c == (trafficEntryCounters{})
}

func monotonicDelta(current, previous uint64) uint64 {
	if current > previous {
		return current - previous
	}
	return 0
}

func addSnapshotCounters(snapshot *TrafficSnapshot, delta trafficCounters) {
	snapshot.TXBytes = saturatingAdd(snapshot.TXBytes, delta.txBytes)
	snapshot.RXBytes = saturatingAdd(snapshot.RXBytes, delta.rxBytes)
	snapshot.TXPackets = saturatingAdd(snapshot.TXPackets, delta.txPackets)
	snapshot.RXPackets = saturatingAdd(snapshot.RXPackets, delta.rxPackets)
	snapshot.DroppedBytes = saturatingAdd(snapshot.DroppedBytes, delta.droppedBytes)
	snapshot.DroppedPackets = saturatingAdd(snapshot.DroppedPackets, delta.droppedPackets)
}

func addEntryCounters(entry *TrafficEntry, delta trafficEntryCounters) {
	entry.TXBytes = saturatingAdd(entry.TXBytes, delta.txBytes)
	entry.RXBytes = saturatingAdd(entry.RXBytes, delta.rxBytes)
	entry.TXPackets = saturatingAdd(entry.TXPackets, delta.txPackets)
	entry.RXPackets = saturatingAdd(entry.RXPackets, delta.rxPackets)
}

func setEntryCounters(entry *TrafficEntry, counters trafficEntryCounters) {
	entry.TXBytes = counters.txBytes
	entry.RXBytes = counters.rxBytes
	entry.TXPackets = counters.txPackets
	entry.RXPackets = counters.rxPackets
}

func saturatingAdd(a, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}

// validMergedTrafficEntry validates retained, peer-controlled strings in a
// worker snapshot. The control frame is bounded, but without field limits a
// worker could rotate near-frame-sized strings through pulls indefinitely.
func validMergedTrafficEntry(entry TrafficEntry) bool {
	return validTrafficText(entry.Host, maxTrafficHostBytes, true) &&
		validTrafficText(entry.Address, maxTrafficAddressBytes, false) &&
		validTrafficText(entry.Protocol, maxTrafficProtocolBytes, false)
}

func validTrafficText(value string, maxBytes int, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || len(value) > maxBytes || !utf8.ValidString(value) {
		return false
	}
	return strings.IndexFunc(value, unicode.IsControl) < 0
}
