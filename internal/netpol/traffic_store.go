package netpol

import (
	"sort"
	"sync"
	"time"
)

// trafficStore is the sole owner of mutable traffic aggregates. Callers can
// submit observations or remote deltas and take immutable snapshots; they do
// not receive references to retained entries or DNS state.
type trafficStore struct {
	mu       sync.Mutex
	snapshot TrafficSnapshot
	entries  map[trafficEntryKey]*TrafficEntry
	dns      trafficDNSCache
	dirty    bool
}

type remoteTrafficEntry struct {
	key   trafficEntryKey
	entry TrafficEntry
	delta trafficEntryCounters
}

func newTrafficStore(snapshot TrafficSnapshot) *trafficStore {
	store := &trafficStore{
		snapshot: TrafficSnapshot{Version: trafficSnapshotVersion},
		entries:  make(map[trafficEntryKey]*TrafficEntry),
		dns:      newTrafficDNSCache(),
	}
	if snapshot.Version != trafficSnapshotVersion {
		return store
	}
	store.snapshot = snapshot
	store.snapshot.Entries = nil
	for i := range snapshot.Entries {
		if len(store.entries) >= maxTrafficEntries {
			break
		}
		entry := snapshot.Entries[i]
		key := makeTrafficEntryKey(entry.Address, entry.Host, entry.Protocol, entry.Port, entry.Allowed)
		copy := entry
		store.entries[key] = &copy
	}
	return store
}

func (s *trafficStore) observeTX(frame []byte, allowed bool, now time.Time) {
	s.observe(inspectTrafficFrame(frame), trafficOutbound, allowed, now)
}

func (s *trafficStore) observeRX(frame []byte, now time.Time) {
	s.observe(inspectTrafficFrame(frame), trafficInbound, true, now)
}

func (s *trafficStore) observe(frame inspectedTrafficFrame, direction trafficDirection, allowed bool, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.countFrame(direction, allowed, len(frame.raw))
	observation, retain := classifyTrafficObservation(frame, direction, allowed, &s.dns, now)
	if retain {
		s.record(observation, direction, len(frame.raw), now)
	}
}

func (s *trafficStore) countFrame(direction trafficDirection, allowed bool, size int) {
	if direction == trafficOutbound {
		s.snapshot.TXBytes += uint64(size)
		s.snapshot.TXPackets++
		if !allowed {
			s.snapshot.DroppedBytes += uint64(size)
			s.snapshot.DroppedPackets++
		}
	} else {
		s.snapshot.RXBytes += uint64(size)
		s.snapshot.RXPackets++
	}
	s.dirty = true
}

func (s *trafficStore) record(observation trafficObservation, direction trafficDirection, size int, now time.Time) {
	key := makeTrafficEntryKey(
		observation.address,
		observation.host,
		observation.protocol,
		observation.port,
		observation.allowed,
	)
	entry := s.entries[key]
	if entry == nil {
		if len(s.entries) >= maxTrafficEntries {
			return
		}
		entry = &TrafficEntry{
			Host:      observation.host,
			Address:   observation.address,
			Protocol:  observation.protocol,
			Port:      observation.port,
			Allowed:   observation.allowed,
			FirstSeen: now,
		}
		s.entries[key] = entry
	} else if observation.host != "" && observation.host != observation.address {
		entry.Host = observation.host
	}
	entry.LastSeen = now
	if direction == trafficOutbound {
		entry.TXBytes += uint64(size)
		entry.TXPackets++
	} else {
		entry.RXBytes += uint64(size)
		entry.RXPackets++
	}
}

// mergeRemote applies one epoch update atomically. The returned flags tell the
// epoch which entry watermarks were accepted; rejected new keys must not consume
// its bounded watermark capacity.
func (s *trafficStore) mergeRemote(counters trafficCounters, updates []remoteTrafficEntry) []bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !counters.zero() {
		addSnapshotCounters(&s.snapshot, counters)
		s.dirty = true
	}
	accepted := make([]bool, len(updates))
	for i := range updates {
		accepted[i] = s.mergeEntry(updates[i])
	}
	return accepted
}

func (s *trafficStore) mergeEntry(update remoteTrafficEntry) bool {
	current, exists := s.entries[update.key]
	if !exists {
		if len(s.entries) >= maxTrafficEntries {
			return false
		}
		copy := update.entry
		setEntryCounters(&copy, update.delta)
		s.entries[update.key] = &copy
		s.dirty = true
		return true
	}
	changed := !update.delta.zero()
	addEntryCounters(current, update.delta)
	if update.entry.FirstSeen.Before(current.FirstSeen) {
		current.FirstSeen = update.entry.FirstSeen
		changed = true
	}
	if update.entry.LastSeen.After(current.LastSeen) {
		current.LastSeen = update.entry.LastSeen
		changed = true
	}
	if shouldReplaceTrafficHost(current, update.entry) {
		current.Host = update.entry.Host
		changed = true
	}
	if changed {
		s.dirty = true
	}
	return true
}

func shouldReplaceTrafficHost(current *TrafficEntry, update TrafficEntry) bool {
	if update.Host == "" || update.Host == update.Address {
		return false
	}
	return current.Host == "" || current.Host == current.Address
}

func (s *trafficStore) snapshotAt(now time.Time) TrafficSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked(now)
}

func (s *trafficStore) takeDirtySnapshot(now time.Time) (TrafficSnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return TrafficSnapshot{}, false
	}
	snapshot := s.snapshotLocked(now)
	s.dirty = false
	return snapshot, true
}

func (s *trafficStore) markDirty() {
	s.mu.Lock()
	s.dirty = true
	s.mu.Unlock()
}

func (s *trafficStore) snapshotLocked(now time.Time) TrafficSnapshot {
	snapshot := s.snapshot
	snapshot.Version = trafficSnapshotVersion
	snapshot.Updated = now
	snapshot.Entries = make([]TrafficEntry, 0, len(s.entries))
	for _, entry := range s.entries {
		snapshot.Entries = append(snapshot.Entries, *entry)
	}
	sort.Slice(snapshot.Entries, func(i, j int) bool {
		return snapshot.Entries[i].LastSeen.After(snapshot.Entries[j].LastSeen)
	})
	return snapshot
}

type trafficEntryKey struct {
	peer     string
	protocol string
	port     uint16
	allowed  bool
}

func makeTrafficEntryKey(address, host, protocol string, port uint16, allowed bool) trafficEntryKey {
	// DNS rows are keyed by host because every query goes to the same gateway.
	peer := address
	if protocol == "dns" {
		peer = host
	}
	return trafficEntryKey{peer: peer, protocol: protocol, port: port, allowed: allowed}
}
