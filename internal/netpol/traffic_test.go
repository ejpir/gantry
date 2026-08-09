package netpol

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func inboundFrame(t *testing.T, sourceIP string, protocol uint8, sourcePort uint16, payload []byte) []byte {
	t.Helper()
	frame := ipFrame(t, "192.168.127.2", protocol, 12345, payload)
	copy(frame[14+12:14+16], net.ParseIP(sourceIP).To4())
	if protocol == protoTCP || protocol == protoUDP {
		binary.BigEndian.PutUint16(frame[14+20:14+22], sourcePort)
	}
	return frame
}

func TestTrafficRecorderAggregatesPolicyAndDNS(t *testing.T) {
	path := filepath.Join(t.TempDir(), TrafficFileName)
	recorder := NewTrafficRecorder(path)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("initial traffic marker: %v", err)
	}

	query := ipFrame(t, gatewayIP, protoUDP, 53, dnsQuery(t, "example.com"))
	recorder.ObserveTX(query, true)
	answer := inboundFrame(t, gatewayIP, protoUDP, 53, dnsAnswer(t, "example.com", "93.184.216.34"))
	recorder.ObserveRX(answer)

	httpsTX := ipFrame(t, "93.184.216.34", protoTCP, 443, []byte("request"))
	httpsRX := inboundFrame(t, "93.184.216.34", protoTCP, 443, []byte("response"))
	recorder.ObserveTX(httpsTX, true)
	recorder.ObserveRX(httpsRX)
	recorder.ObserveTX(ipFrame(t, "203.0.113.7", protoTCP, 80, nil), false)

	snapshot := recorder.Snapshot()
	if snapshot.TXPackets != 3 || snapshot.RXPackets != 2 || snapshot.DroppedPackets != 1 {
		t.Fatalf("traffic totals = tx:%d rx:%d dropped:%d", snapshot.TXPackets, snapshot.RXPackets, snapshot.DroppedPackets)
	}
	var dnsRow, httpsRow, blockedRow *TrafficEntry
	for i := range snapshot.Entries {
		entry := &snapshot.Entries[i]
		switch {
		case entry.Protocol == "dns" && entry.Host == "example.com":
			dnsRow = entry
		case entry.Protocol == "tcp" && entry.Port == 443:
			httpsRow = entry
		case !entry.Allowed:
			blockedRow = entry
		}
	}
	if dnsRow == nil || dnsRow.TXPackets != 1 || dnsRow.RXPackets != 1 {
		t.Fatalf("DNS row = %#v", dnsRow)
	}
	if httpsRow == nil || httpsRow.Host != "example.com" || httpsRow.TXPackets != 1 || httpsRow.RXPackets != 1 {
		t.Fatalf("HTTPS row = %#v", httpsRow)
	}
	if blockedRow == nil || blockedRow.Address != "203.0.113.7" || blockedRow.TXPackets != 1 {
		t.Fatalf("blocked row = %#v", blockedRow)
	}

	recorder.Close()
	persisted, err := ReadTrafficSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.TXPackets != snapshot.TXPackets || len(persisted.Entries) != len(snapshot.Entries) {
		t.Fatalf("persisted snapshot = %#v", persisted)
	}
}

func TestTrafficRecorderShowsBlockedIPv6Destination(t *testing.T) {
	recorder := NewTrafficRecorder(filepath.Join(t.TempDir(), TrafficFileName))
	frame := make([]byte, 14+40+20)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv6)
	frame[14] = 6 << 4
	frame[14+6] = protoTCP
	copy(frame[14+8:14+24], net.ParseIP("fd00::2").To16())
	copy(frame[14+24:14+40], net.ParseIP("2606:4700:4700::1111").To16())
	binary.BigEndian.PutUint16(frame[14+40:14+42], 12345)
	binary.BigEndian.PutUint16(frame[14+42:14+44], 443)
	recorder.ObserveTX(frame, false)
	snapshot := recorder.Snapshot()
	recorder.Close()
	if len(snapshot.Entries) != 1 || snapshot.Entries[0].Address != "2606:4700:4700::1111" || snapshot.Entries[0].Protocol != "tcp6" || snapshot.Entries[0].Port != 443 || snapshot.Entries[0].Allowed {
		t.Fatalf("IPv6 traffic row = %#v", snapshot.Entries)
	}
}

func TestTrafficRecorderResumesSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), TrafficFileName)
	first := NewTrafficRecorder(path)
	first.ObserveTX(ipFrame(t, "1.1.1.1", protoUDP, 443, nil), true)
	first.Close()

	second := NewTrafficRecorder(path)
	second.ObserveTX(ipFrame(t, "1.1.1.1", protoUDP, 443, nil), true)
	snapshot := second.Snapshot()
	second.Close()
	if snapshot.TXPackets != 2 || len(snapshot.Entries) != 1 || snapshot.Entries[0].TXPackets != 2 {
		t.Fatalf("resumed snapshot = %#v", snapshot)
	}
}

func TestSyncSnapshot(t *testing.T) {
	now := time.Now()
	worker := TrafficSnapshot{
		Version: trafficSnapshotVersion, Updated: now,
		TXBytes: 1000, TXPackets: 10, DroppedBytes: 60, DroppedPackets: 2,
		Entries: []TrafficEntry{
			{Host: "example.com", Address: "93.184.216.34", Protocol: "tcp", Port: 443, Allowed: true,
				TXBytes: 900, TXPackets: 9, FirstSeen: now.Add(-time.Hour), LastSeen: now},
			{Address: "192.168.1.20", Protocol: "tcp", Port: 22,
				TXBytes: 100, TXPackets: 1, FirstSeen: now.Add(-time.Minute), LastSeen: now},
		},
	}
	sup := NewTrafficRecorder("")
	sup.SyncSnapshot(worker)
	got := sup.Snapshot()
	if got.TXBytes != 1000 || got.DroppedPackets != 2 {
		t.Fatalf("top-level counters: %+v", got)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("entries: %+v", got.Entries)
	}
	// Monotonic merge: a stale pull never shrinks counters.
	stale := worker
	stale.TXBytes = 10
	stale.Entries[0].TXBytes = 1
	sup.SyncSnapshot(stale)
	got = sup.Snapshot()
	if got.TXBytes != 1000 {
		t.Fatalf("stale pull shrank TXBytes: %+v", got)
	}
	for _, e := range got.Entries {
		if e.Host == "example.com" && e.TXBytes != 900 {
			t.Fatalf("stale pull shrank entry: %+v", e)
		}
		if e.Host == "example.com" && e.FirstSeen != now.Add(-time.Hour) {
			t.Fatalf("FirstSeen not preserved: %+v", e)
		}
	}
	// A later pull advances counters.
	later := worker
	later.TXBytes = 2000
	sup.SyncSnapshot(later)
	if got := sup.Snapshot(); got.TXBytes != 2000 {
		t.Fatalf("later pull did not advance: %+v", got)
	}
}

func TestSyncSnapshotCapsRotatingWorkerEntries(t *testing.T) {
	now := time.Now()
	entry := func(prefix string, i int) TrafficEntry {
		return TrafficEntry{
			Host: prefix + ".example", Address: fmt.Sprintf("2001:db8::%x", i),
			Protocol: "tcp6", Port: 443, Allowed: true, TXPackets: 1,
			FirstSeen: now, LastSeen: now,
		}
	}
	recorder := NewTrafficRecorder("")
	defer recorder.Close()
	first := TrafficSnapshot{Version: trafficSnapshotVersion, Entries: make([]TrafficEntry, maxTrafficEntries+64)}
	for i := range first.Entries {
		first.Entries[i] = entry("first", i)
	}
	recorder.SyncSnapshot(first)
	if got := len(recorder.Snapshot().Entries); got != maxTrafficEntries {
		t.Fatalf("first merge retained %d entries, want %d", got, maxTrafficEntries)
	}

	// At capacity, existing keys still advance while new keys—and a later
	// pull containing an entirely new key set—cannot grow the map.
	existing := first.Entries[0]
	existing.TXPackets = 99
	second := TrafficSnapshot{Version: trafficSnapshotVersion, Entries: []TrafficEntry{existing}}
	for i := 0; i < maxTrafficEntries; i++ {
		second.Entries = append(second.Entries, entry("second", i))
	}
	recorder.SyncSnapshot(second)
	rotated := TrafficSnapshot{Version: trafficSnapshotVersion, Entries: make([]TrafficEntry, maxTrafficEntries)}
	for i := range rotated.Entries {
		rotated.Entries[i] = entry("rotated", i)
	}
	recorder.SyncSnapshot(rotated)
	got := recorder.Snapshot()
	if len(got.Entries) != maxTrafficEntries {
		t.Fatalf("rotating merges retained %d entries, want %d", len(got.Entries), maxTrafficEntries)
	}
	var found bool
	for _, e := range got.Entries {
		if e.Host == existing.Host && e.Address == existing.Address {
			found = true
			if e.TXPackets != 99 {
				t.Fatalf("existing entry did not advance at capacity: %+v", e)
			}
		}
	}
	if !found {
		t.Fatal("existing entry disappeared at capacity")
	}
}

func TestSyncSnapshotValidatesWorkerTelemetry(t *testing.T) {
	recorder := NewTrafficRecorder("")
	defer recorder.Close()
	valid := TrafficEntry{Host: "example.com", Address: "192.0.2.1", Protocol: "tcp", Port: 443}
	recorder.SyncSnapshot(TrafficSnapshot{
		Version: trafficSnapshotVersion + 1, TXPackets: 99, Entries: []TrafficEntry{valid},
	})
	if got := recorder.Snapshot(); got.TXPackets != 0 || len(got.Entries) != 0 {
		t.Fatalf("wrong-version worker snapshot was merged: %+v", got)
	}

	recorder.SyncSnapshot(TrafficSnapshot{
		Version: trafficSnapshotVersion, TXPackets: 7,
		Entries: []TrafficEntry{
			{Host: strings.Repeat("h", maxTrafficHostBytes+1), Address: "192.0.2.2", Protocol: "tcp"},
			{Host: "bad\x1bhost", Address: "192.0.2.3", Protocol: "tcp"},
			{Address: strings.Repeat("a", maxTrafficAddressBytes+1), Protocol: "tcp"},
			{Address: "", Protocol: "tcp"},
			{Address: "192.0.2.4", Protocol: strings.Repeat("p", maxTrafficProtocolBytes+1)},
			{Address: "192.0.2.5", Protocol: ""},
			valid,
		},
	})
	got := recorder.Snapshot()
	if got.TXPackets != 7 {
		t.Fatalf("valid top-level counters were not merged: %+v", got)
	}
	if len(got.Entries) != 1 || got.Entries[0].Host != valid.Host {
		t.Fatalf("invalid worker entries were retained: %+v", got.Entries)
	}
}
