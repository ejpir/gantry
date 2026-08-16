package dashboard

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const (
	tuiMaxPacketRows = 2000
	packetPollEvery  = 750 * time.Millisecond
)

type tuiPacketRow struct {
	Sandbox   string
	Sequence  uint64
	Timestamp time.Time
	Direction packetcapture.Direction
	Allowed   bool
	Length    int
	Captured  int
	Source    string
	Target    string
	Protocol  string
	Info      string
	Layers    string
	Data      []byte
}

type tuiPacketCaptureMsg struct {
	rows    []tuiPacketRow
	after   map[string]uint64
	evicted uint64
	err     string
}

func (m *sandboxTUIModel) refreshPacketsCmd() tea.Cmd {
	if m.packetLoading || m.packetPaused {
		return nil
	}
	targets := make([]string, 0, len(m.sandboxes))
	for _, sandbox := range m.sandboxes {
		if sandbox.State == tuiRunning && sandbox.Net {
			targets = append(targets, sandbox.Name)
		}
	}
	after := make(map[string]uint64, len(m.packetAfter))
	for name, sequence := range m.packetAfter {
		after[name] = sequence
	}
	m.packetLoading = true
	return func() tea.Msg {
		message := tuiPacketCaptureMsg{after: after}
		var failures []string
		for _, name := range targets {
			cursor := message.after[name]
			snapshot, err := m.service.CapturePackets(name, packetcapture.Request{
				Start: true, After: cursor, MaxPackets: 128, MaxBytes: 128 << 10,
			})
			// A restarted sandbox has a fresh recorder and sequence space. Retry
			// from its beginning instead of permanently waiting on the old cursor.
			if err == nil && snapshot.Latest < cursor {
				snapshot, err = m.service.CapturePackets(name, packetcapture.Request{
					Start: true, MaxPackets: 128, MaxBytes: 128 << 10,
				})
			}
			if err != nil {
				failures = append(failures, name+": "+err.Error())
				continue
			}
			message.after[name] = snapshot.Next
			message.evicted += snapshot.Evicted
			for _, packet := range snapshot.Packets {
				message.rows = append(message.rows, decodePacketRow(name, packet))
			}
		}
		message.err = strings.Join(failures, "; ")
		return message
	}
}

func packetPollCmd() tea.Cmd {
	return tea.Tick(packetPollEvery, func(time.Time) tea.Msg { return tuiPacketPollMsg{} })
}

func (m *sandboxTUIModel) handlePacketCapture(message tuiPacketCaptureMsg) (tea.Model, tea.Cmd) {
	m.packetLoading = false
	m.packetAfter = message.after
	m.packetEvicted = message.evicted
	m.packetError = safeUILine(message.err)
	wasFollowing := len(m.packets) == 0 || m.packetCursor == len(m.packets)-1
	m.packets = append(m.packets, message.rows...)
	sort.SliceStable(m.packets, func(left, right int) bool {
		if m.packets[left].Timestamp.Equal(m.packets[right].Timestamp) {
			if m.packets[left].Sandbox == m.packets[right].Sandbox {
				return m.packets[left].Sequence < m.packets[right].Sequence
			}
			return m.packets[left].Sandbox < m.packets[right].Sandbox
		}
		return m.packets[left].Timestamp.Before(m.packets[right].Timestamp)
	})
	if len(m.packets) > tuiMaxPacketRows {
		drop := len(m.packets) - tuiMaxPacketRows
		m.packets = append([]tuiPacketRow(nil), m.packets[drop:]...)
		if !wasFollowing {
			m.packetCursor = max(0, m.packetCursor-drop)
		}
	}
	if wasFollowing && len(m.packets) > 0 {
		m.packetCursor = len(m.packets) - 1
	}
	m.ensureTableCursorVisible()
	if m.page == tuiPacketsPage && !m.packetPaused {
		return m, packetPollCmd()
	}
	return m, nil
}

func (m *sandboxTUIModel) updatePacketActionKey(key string) (tea.Cmd, bool) {
	switch key {
	case "d", "enter":
		m.openPacketDetail()
		return nil, true
	case "space":
		m.packetPaused = !m.packetPaused
		if !m.packetPaused {
			return m.refreshPacketsCmd(), true
		}
		return nil, true
	case "c":
		return m.clearPacketsCmd(), true
	case "r", "R":
		return m.refreshPacketsCmd(), true
	default:
		return nil, false
	}
}

func (m *sandboxTUIModel) clearPacketsCmd() tea.Cmd {
	if m.packetLoading {
		return nil
	}
	targets := make([]string, 0, len(m.sandboxes))
	for _, sandbox := range m.sandboxes {
		if sandbox.State == tuiRunning && sandbox.Net {
			targets = append(targets, sandbox.Name)
		}
	}
	m.packets = nil
	m.packetCursor, m.packetScroll = 0, 0
	m.packetAfter = make(map[string]uint64)
	m.packetEvicted = 0
	m.packetError = ""
	m.packetLoading = true
	return func() tea.Msg {
		message := tuiPacketCaptureMsg{after: make(map[string]uint64)}
		var failures []string
		for _, name := range targets {
			if _, err := m.service.CapturePackets(name, packetcapture.Request{Start: true, Clear: true}); err != nil {
				failures = append(failures, name+": "+err.Error())
			}
		}
		message.err = strings.Join(failures, "; ")
		return message
	}
}

func (m sandboxTUIModel) renderPacketsView(theme tuiTheme, layout tuiDashboardLayout) string {
	if len(m.packets) == 0 {
		switch {
		case m.packetLoading:
			return m.renderTableLoading(theme, layout, "Starting memory-only packet capture…")
		case m.packetError != "":
			return m.renderTableEmpty(theme, layout, "Packet capture unavailable", m.packetError+". Restart older running sandboxes with this Gantry build.")
		case !m.hasPacketCaptureTarget():
			return m.renderTableEmpty(theme, layout, "No running network sandbox", "Start a network-enabled sandbox, then return here to capture its virtual Ethernet traffic.")
		default:
			return m.renderTableEmpty(theme, layout, "Waiting for packets", "Capture is active in bounded memory. Generate network traffic inside a sandbox.")
		}
	}
	return m.renderPopulatedTable(theme, layout, tuiPacketsPage)
}

func (m sandboxTUIModel) hasPacketCaptureTarget() bool {
	for _, sandbox := range m.sandboxes {
		if sandbox.State == tuiRunning && sandbox.Net {
			return true
		}
	}
	return false
}

func (m sandboxTUIModel) renderPacketsHeader(theme tuiTheme, width int) string {
	style := lipgloss.NewStyle().Bold(true).Foreground(theme.muted)
	if width >= 100 {
		endpoint := maxInt(14, (width-50)/2)
		return style.Render(tableCell("TIME", 12) + " " + tableCell("SANDBOX", 13) + " " + tableCell("DIR", 4) + " " +
			tableCell("SOURCE", endpoint) + " " + tableCell("DESTINATION", endpoint) + " " + tableCell("PROTO", 7) + " " + tableCell("LEN", 6) + " INFO")
	}
	if width >= 62 {
		endpoint := maxInt(12, (width-31)/2)
		return style.Render(tableCell("TIME", 9) + " " + tableCell("VM", 11) + " " + tableCell("D", 2) + " " +
			tableCell("SOURCE", endpoint) + " " + tableCell("DEST", endpoint) + " " + tableCell("PROTO", 6))
	}
	return style.Render(tableCell("", 2) + " " + tableCell("SANDBOX", 11) + " " + tableCell("PACKET", maxInt(1, width-16)))
}

func (m sandboxTUIModel) renderPacketRow(theme tuiTheme, row tuiPacketRow, width int) string {
	direction := "→"
	if row.Direction == packetcapture.RX {
		direction = "←"
	}
	if row.Direction == packetcapture.TX && !row.Allowed {
		direction = lipgloss.NewStyle().Foreground(theme.error).Render("×")
	}
	if width >= 100 {
		endpoint := maxInt(14, (width-50)/2)
		return tableCell(row.Timestamp.Local().Format("15:04:05.000"), 12) + " " + tableCell(row.Sandbox, 13) + " " + tableCell(direction, 4) + " " +
			tableCell(row.Source, endpoint) + " " + tableCell(row.Target, endpoint) + " " + tableCell(row.Protocol, 7) + " " +
			tableCell(fmt.Sprint(row.Length), 6) + " " + row.Info
	}
	if width >= 62 {
		endpoint := maxInt(12, (width-31)/2)
		return tableCell(row.Timestamp.Local().Format("15:04:05"), 9) + " " + tableCell(row.Sandbox, 11) + " " + tableCell(direction, 2) + " " +
			tableCell(row.Source, endpoint) + " " + tableCell(row.Target, endpoint) + " " + tableCell(row.Protocol, 6)
	}
	return tableCell(direction, 2) + " " + tableCell(row.Sandbox, 11) + " " + tableCell(row.Protocol+" "+row.Source+" → "+row.Target, maxInt(1, width-16))
}

func (m sandboxTUIModel) renderPacketDetail(theme tuiTheme, width int) []string {
	if m.packetCursor < 0 || m.packetCursor >= len(m.packets) || m.tableDetailHeight() == 0 {
		return nil
	}
	row := m.packets[m.packetCursor]
	decision := "allowed"
	decisionStyle := lipgloss.NewStyle().Foreground(theme.success)
	if row.Direction == packetcapture.TX && !row.Allowed {
		decision = "blocked"
		decisionStyle = lipgloss.NewStyle().Foreground(theme.error)
	}
	payload := fmt.Sprintf("% x", row.Data[:min(len(row.Data), 32)])
	return []string{
		m.renderTableSeparator(theme, width),
		lipgloss.NewStyle().Bold(true).Foreground(theme.text).Render(fmt.Sprintf("%s packet #%d", row.Sandbox, row.Sequence)) + "  " + decisionStyle.Render(decision),
		lipgloss.NewStyle().Foreground(theme.muted).Render("flow     ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(row.Source+" → "+row.Target),
		lipgloss.NewStyle().Foreground(theme.muted).Render("layers   ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(defaultText(row.Layers, "decode unavailable")),
		lipgloss.NewStyle().Foreground(theme.muted).Render("capture  ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(fmt.Sprintf("%d/%d bytes at %s", row.Captured, row.Length, row.Timestamp.Local().Format(time.RFC3339Nano))),
		lipgloss.NewStyle().Foreground(theme.muted).Render("hex      ") + lipgloss.NewStyle().Foreground(theme.secondary).Render(payload),
	}
}

func decodePacketRow(sandbox string, record packetcapture.Packet) tuiPacketRow {
	row := tuiPacketRow{
		Sandbox: sandbox, Sequence: record.Sequence, Timestamp: record.Timestamp,
		Direction: record.Direction, Allowed: record.Allowed, Length: record.Length,
		Captured: len(record.Data), Source: "—", Target: "—", Protocol: "ETH",
		Data: append([]byte(nil), record.Data...),
	}
	packet := gopacket.NewPacket(record.Data, layers.LayerTypeEthernet, gopacket.Default)
	decodedLayers := packet.Layers()
	layerNames := make([]string, 0, len(decodedLayers))
	for _, layer := range decodedLayers {
		layerNames = append(layerNames, layer.LayerType().String())
	}
	row.Layers = safeUILine(strings.Join(layerNames, " › "))
	if network := packet.NetworkLayer(); network != nil {
		source, target := network.NetworkFlow().Endpoints()
		row.Source, row.Target = source.String(), target.String()
	}
	if transport := packet.TransportLayer(); transport != nil {
		source, target := transport.TransportFlow().Endpoints()
		row.Source = joinPacketEndpoint(row.Source, source.String())
		row.Target = joinPacketEndpoint(row.Target, target.String())
	}

	switch {
	case packet.Layer(layers.LayerTypeDNS) != nil:
		row.Protocol = "DNS"
		dnsLayer, _ := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
		if dnsLayer != nil && len(dnsLayer.Questions) > 0 {
			verb := "query"
			if dnsLayer.QR {
				verb = "response"
			}
			row.Info = verb + " " + string(dnsLayer.Questions[0].Name)
		}
	case packet.Layer(layers.LayerTypeTCP) != nil:
		row.Protocol = "TCP"
		tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if tcp != nil {
			row.Info = tcpFlags(tcp)
		}
	case packet.Layer(layers.LayerTypeUDP) != nil:
		row.Protocol = "UDP"
	case packet.Layer(layers.LayerTypeICMPv6) != nil:
		row.Protocol = "ICMPv6"
	case packet.Layer(layers.LayerTypeICMPv4) != nil:
		row.Protocol = "ICMP"
	case packet.Layer(layers.LayerTypeARP) != nil:
		row.Protocol = "ARP"
		if arp, ok := packet.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
			row.Source = net.IP(arp.SourceProtAddress).String()
			row.Target = net.IP(arp.DstProtAddress).String()
		}
	case packet.Layer(layers.LayerTypeIPv6) != nil:
		row.Protocol = "IPv6"
	case packet.Layer(layers.LayerTypeIPv4) != nil:
		row.Protocol = "IPv4"
	}
	if decoding := packet.ErrorLayer(); decoding != nil {
		message := "decode: " + decoding.Error().Error()
		if row.Info == "" {
			row.Info = message
		} else {
			row.Info += " · " + message
		}
	}
	row.Source = safeUILine(row.Source)
	row.Target = safeUILine(row.Target)
	row.Info = safeUILine(row.Info)
	return row
}

func joinPacketEndpoint(address, port string) string {
	if address == "" || address == "—" {
		return port
	}
	if strings.Contains(address, ":") {
		return "[" + address + "]:" + port
	}
	return address + ":" + port
}

func tcpFlags(tcp *layers.TCP) string {
	flags := make([]string, 0, 6)
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	sort.Strings(flags)
	return strings.Join(flags, ",")
}
