package netpol

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
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
