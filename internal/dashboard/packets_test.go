package dashboard

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/ejpir/gantry/internal/sandbox"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func TestDecodePacketRow(t *testing.T) {
	row := testTCPPacketRow(t)
	if row.Sandbox != "dev" || row.Sequence != 7 || row.Protocol != "TCP" {
		t.Fatalf("packet identity = %+v", row)
	}
	if row.Source != "192.0.2.10:32123" || row.Target != "198.51.100.20:443" {
		t.Fatalf("packet flow = %q -> %q", row.Source, row.Target)
	}
	if row.Info != "ACK,SYN" || !strings.Contains(row.Layers, "Ethernet") || !strings.Contains(row.Layers, "TCP") {
		t.Fatalf("packet decode = info %q layers %q", row.Info, row.Layers)
	}
}

func testTCPPacketRow(t *testing.T) tuiPacketRow {
	t.Helper()
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.ParseIP("192.0.2.10"), DstIP: net.ParseIP("198.51.100.20"),
	}
	tcp := &layers.TCP{SrcPort: 32123, DstPort: 443, SYN: true, ACK: true}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
			DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
			EthernetType: layers.EthernetTypeIPv4,
		}, ip, tcp, gopacket.Payload("hello")); err != nil {
		t.Fatal(err)
	}

	return decodePacketRow("dev", packetcapture.Packet{
		Sequence: 7, Timestamp: time.Unix(123, 456), Direction: packetcapture.TX,
		Allowed: false, Length: len(buffer.Bytes()), Data: buffer.Bytes(),
	})
}

func TestRenderPacketsView(t *testing.T) {
	m := newSandboxTUIModel(sandbox.NewDashboardService())
	m.loading = false
	m.page = tuiPacketsPage
	m.width, m.height = 110, 28
	m.packets = []tuiPacketRow{{
		Sandbox: "dev", Sequence: 1, Timestamp: time.Unix(123, 456),
		Direction: packetcapture.TX, Allowed: true, Length: 60, Captured: 60,
		Source: "192.0.2.10:32123", Target: "198.51.100.20:443", Protocol: "TCP",
		Info: "SYN", Layers: "Ethernet › IPv4 › TCP", Data: []byte{0xde, 0xad, 0xbe, 0xef},
	}}

	plain := ansi.Strip(m.View().Content)
	for _, want := range []string{"PACKETS", "192.0.2.10:32123", "198.51.100.20:443", "Ethernet › IPv4 › TCP", "de ad be ef"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("packet view does not contain %q:\n%s", want, plain)
		}
	}
}

func TestPacketDetailDialog(t *testing.T) {
	m := newSandboxTUIModel(sandbox.NewDashboardService())
	m.loading = false
	m.page = tuiPacketsPage
	m.width, m.height = 110, 32
	m.packets = []tuiPacketRow{testTCPPacketRow(t)}

	cmd, handled := m.updatePacketActionKey("d")
	if !handled || cmd != nil || m.dialog != tuiPacketDetailDialog || m.packetDetail == nil {
		t.Fatalf("open details = handled %v cmd=%v dialog=%d detail=%v", handled, cmd, m.dialog, m.packetDetail)
	}
	plain := ansi.Strip(m.renderPacketDetailDialog(tuiThemeFor(m.dark), 90))
	for _, want := range []string{
		"Packet #7 · dev", "CAPTURE", "blocked", "ETHERNET", "02:00:00:00:00:01",
		"IPv4", "192.0.2.10", "TCP", "32123 → 443", "ACK SYN", "CAPTURED BYTES", "hello",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("packet detail does not contain %q:\n%s", want, plain)
		}
	}

	// The inspector holds the selected frame stable while live capture keeps
	// updating the table underneath it.
	m.packets[0].Data[0] ^= 0xff
	if m.packetDetail.Data[0] == m.packets[0].Data[0] {
		t.Fatal("packet detail aliases the live table buffer")
	}
	_, _ = m.updateDialogKey(tea.KeyPressMsg{Code: 'd'})
	if m.dialog != tuiNoDialog || m.packetDetail != nil {
		t.Fatalf("close details = dialog %d detail=%v", m.dialog, m.packetDetail)
	}
}
