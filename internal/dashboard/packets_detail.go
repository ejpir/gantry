package dashboard

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"charm.land/lipgloss/v2"
)

func (m *sandboxTUIModel) openPacketDetail() bool {
	if m.packetCursor < 0 || m.packetCursor >= len(m.packets) {
		return false
	}
	detail := m.packets[m.packetCursor]
	detail.Data = append([]byte(nil), detail.Data...)
	m.packetDetail = &detail
	m.dialog = tuiPacketDetailDialog
	m.dialogScroll = 0
	return true
}

func (m sandboxTUIModel) renderPacketDetailDialog(theme tuiTheme, width int) string {
	row := m.packetDetail
	if row == nil {
		return m.dialogHeader(theme, "Packet details", width) + "\n\n" +
			lipgloss.NewStyle().Foreground(theme.muted).Render("No packet selected.")
	}

	section := func(title string) string {
		return lipgloss.NewStyle().Bold(true).Foreground(theme.accent).Render(title)
	}
	field := func(label, value string) string {
		label = lipgloss.NewStyle().Foreground(theme.muted).Width(17).Render(label)
		return label + lipgloss.NewStyle().Foreground(theme.secondary).Render(safeUILine(value))
	}
	lines := []string{
		m.dialogHeader(theme, fmt.Sprintf("Packet #%d · %s", row.Sequence, row.Sandbox), width),
		"",
		section("CAPTURE"),
		field("Time", row.Timestamp.Local().Format("2006-01-02 15:04:05.000000000 -0700")),
		field("Direction", strings.ToUpper(string(row.Direction))),
		field("Decision", packetDecision(*row)),
		field("Frame length", fmt.Sprintf("%d bytes", row.Length)),
		field("Captured", packetCapturedText(*row)),
		field("Summary", row.Protocol+"  "+row.Source+" → "+row.Target),
	}

	packet := gopacket.NewPacket(row.Data, layers.LayerTypeEthernet, gopacket.Default)
	if ethernet, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
		lines = append(lines, "", section("ETHERNET"),
			field("Source MAC", ethernet.SrcMAC.String()),
			field("Destination MAC", ethernet.DstMAC.String()),
			field("EtherType", fmt.Sprintf("%s (0x%04x)", ethernet.EthernetType, uint16(ethernet.EthernetType))),
			field("Header", fmt.Sprintf("%d bytes", len(ethernet.LayerContents()))),
		)
	}
	if vlan, ok := packet.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q); ok {
		lines = append(lines, "", section("802.1Q VLAN"),
			field("VLAN ID", fmt.Sprint(vlan.VLANIdentifier)),
			field("Priority", fmt.Sprint(vlan.Priority)),
			field("Drop eligible", fmt.Sprint(vlan.DropEligible)),
			field("Payload type", fmt.Sprintf("%s (0x%04x)", vlan.Type, uint16(vlan.Type))),
		)
	}
	if arp, ok := packet.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
		lines = append(lines, "", section("ARP"),
			field("Operation", arpOperation(arp.Operation)),
			field("Sender MAC", net.HardwareAddr(arp.SourceHwAddress).String()),
			field("Sender address", net.IP(arp.SourceProtAddress).String()),
			field("Target MAC", net.HardwareAddr(arp.DstHwAddress).String()),
			field("Target address", net.IP(arp.DstProtAddress).String()),
		)
	}
	if ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		lines = append(lines, "", section("IPv4"),
			field("Source", ipv4.SrcIP.String()),
			field("Destination", ipv4.DstIP.String()),
			field("Header / total", fmt.Sprintf("%d / %d bytes", int(ipv4.IHL)*4, ipv4.Length)),
			field("Protocol", fmt.Sprintf("%s (%d)", ipv4.Protocol, uint8(ipv4.Protocol))),
			field("TTL", fmt.Sprint(ipv4.TTL)),
			field("DSCP / ECN", fmt.Sprintf("%d / %d", ipv4.TOS>>2, ipv4.TOS&3)),
			field("Identification", fmt.Sprintf("0x%04x (%d)", ipv4.Id, ipv4.Id)),
			field("Flags / fragment", fmt.Sprintf("%s / %d", ipv4.Flags, ipv4.FragOffset)),
			field("Checksum", fmt.Sprintf("0x%04x", ipv4.Checksum)),
		)
		for index, option := range ipv4.Options {
			lines = append(lines, field(fmt.Sprintf("Option %d", index+1), fmt.Sprintf("type=%d length=%d data=%x", option.OptionType, option.OptionLength, option.OptionData)))
		}
	}
	if ipv6, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		lines = append(lines, "", section("IPv6"),
			field("Source", ipv6.SrcIP.String()),
			field("Destination", ipv6.DstIP.String()),
			field("Payload length", fmt.Sprintf("%d bytes", ipv6.Length)),
			field("Next header", fmt.Sprintf("%s (%d)", ipv6.NextHeader, uint8(ipv6.NextHeader))),
			field("Hop limit", fmt.Sprint(ipv6.HopLimit)),
			field("Traffic class", fmt.Sprintf("0x%02x", ipv6.TrafficClass)),
			field("Flow label", fmt.Sprintf("0x%05x", ipv6.FlowLabel)),
		)
	}
	if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		lines = append(lines, "", section("TCP"),
			field("Ports", fmt.Sprintf("%d → %d", tcp.SrcPort, tcp.DstPort)),
			field("Sequence", fmt.Sprintf("%d (0x%08x)", tcp.Seq, tcp.Seq)),
			field("Acknowledgment", fmt.Sprintf("%d (0x%08x)", tcp.Ack, tcp.Ack)),
			field("Header / payload", fmt.Sprintf("%d / %d bytes", int(tcp.DataOffset)*4, len(tcp.LayerPayload()))),
			field("Flags", packetTCPFlags(tcp)),
			field("Window", fmt.Sprint(tcp.Window)),
			field("Checksum", fmt.Sprintf("0x%04x", tcp.Checksum)),
			field("Urgent pointer", fmt.Sprint(tcp.Urgent)),
		)
		for index, option := range tcp.Options {
			lines = append(lines, field(fmt.Sprintf("Option %d", index+1), fmt.Sprintf("%s length=%d data=%x", option.OptionType, option.OptionLength, option.OptionData)))
		}
	}
	if udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		lines = append(lines, "", section("UDP"),
			field("Ports", fmt.Sprintf("%d → %d", udp.SrcPort, udp.DstPort)),
			field("Length", fmt.Sprintf("%d bytes", udp.Length)),
			field("Payload", fmt.Sprintf("%d bytes", len(udp.LayerPayload()))),
			field("Checksum", fmt.Sprintf("0x%04x", udp.Checksum)),
		)
	}
	if icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
		lines = append(lines, "", section("ICMPv4"),
			field("Type / code", fmt.Sprintf("%s (%d / %d)", icmp.TypeCode, icmp.TypeCode.Type(), icmp.TypeCode.Code())),
			field("Identifier / seq", fmt.Sprintf("%d / %d", icmp.Id, icmp.Seq)),
			field("Checksum", fmt.Sprintf("0x%04x", icmp.Checksum)),
			field("Payload", fmt.Sprintf("%d bytes", len(icmp.LayerPayload()))),
		)
	}
	if icmp, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6); ok {
		lines = append(lines, "", section("ICMPv6"),
			field("Type / code", fmt.Sprintf("%s (%d / %d)", icmp.TypeCode, icmp.TypeCode.Type(), icmp.TypeCode.Code())),
			field("Checksum", fmt.Sprintf("0x%04x", icmp.Checksum)),
			field("Payload", fmt.Sprintf("%d bytes", len(icmp.LayerPayload()))),
		)
	}
	if dns, ok := packet.Layer(layers.LayerTypeDNS).(*layers.DNS); ok {
		lines = append(lines, packetDNSDetail(section, field, dns)...)
	}
	if decoding := packet.ErrorLayer(); decoding != nil {
		lines = append(lines, "", section("DECODE ERROR"), field("Error", decoding.Error().Error()))
	}

	lines = append(lines, "", section("CAPTURED BYTES · HEX / ASCII"))
	if len(row.Data) == 0 {
		lines = append(lines, lipgloss.NewStyle().Foreground(theme.muted).Render("No bytes captured."))
	} else {
		lines = append(lines, lipgloss.NewStyle().Foreground(theme.secondary).Render(strings.TrimSuffix(hex.Dump(row.Data), "\n")))
	}
	lines = append(lines, "", lipgloss.NewStyle().Foreground(theme.muted).Render("↑/↓ scroll  •  PgUp/PgDn page  •  c copy all  •  d / esc close"))
	return strings.Join(lines, "\n")
}

func packetDecision(row tuiPacketRow) string {
	if row.Direction == "tx" && !row.Allowed {
		return "blocked"
	}
	return "allowed"
}

func packetCapturedText(row tuiPacketRow) string {
	if row.Captured < row.Length {
		return fmt.Sprintf("%d bytes (truncated; original %d)", row.Captured, row.Length)
	}
	return fmt.Sprintf("%d bytes (complete)", row.Captured)
}

func packetTCPFlags(tcp *layers.TCP) string {
	var flags []string
	for _, flag := range []struct {
		enabled bool
		name    string
	}{
		{tcp.NS, "NS"}, {tcp.CWR, "CWR"}, {tcp.ECE, "ECE"}, {tcp.URG, "URG"},
		{tcp.ACK, "ACK"}, {tcp.PSH, "PSH"}, {tcp.RST, "RST"}, {tcp.SYN, "SYN"}, {tcp.FIN, "FIN"},
	} {
		if flag.enabled {
			flags = append(flags, flag.name)
		}
	}
	return defaultText(strings.Join(flags, " "), "none")
}

func arpOperation(operation uint16) string {
	switch operation {
	case 1:
		return "request (1)"
	case 2:
		return "reply (2)"
	default:
		return fmt.Sprintf("%d", operation)
	}
}

func packetDNSDetail(section func(string) string, field func(string, string) string, dns *layers.DNS) []string {
	flags := make([]string, 0, 6)
	if dns.QR {
		flags = append(flags, "response")
	} else {
		flags = append(flags, "query")
	}
	if dns.AA {
		flags = append(flags, "authoritative")
	}
	if dns.TC {
		flags = append(flags, "truncated")
	}
	if dns.RD {
		flags = append(flags, "recursion-desired")
	}
	if dns.RA {
		flags = append(flags, "recursion-available")
	}
	lines := []string{"", section("DNS"),
		field("Transaction ID", fmt.Sprintf("0x%04x (%d)", dns.ID, dns.ID)),
		field("Opcode / status", fmt.Sprintf("%s / %s", dns.OpCode, dns.ResponseCode)),
		field("Flags", defaultText(strings.Join(flags, ", "), "none")),
		field("Record counts", fmt.Sprintf("questions=%d answers=%d authority=%d additional=%d", dns.QDCount, dns.ANCount, dns.NSCount, dns.ARCount)),
	}
	for index, question := range dns.Questions {
		if index == 64 {
			lines = append(lines, field("Question", fmt.Sprintf("… %d more questions", len(dns.Questions)-index)))
			break
		}
		lines = append(lines, field(fmt.Sprintf("Question %d", index+1), fmt.Sprintf("%s  %s  %s", question.Name, question.Type, question.Class)))
	}
	appendRecords := func(label string, records []layers.DNSResourceRecord) {
		for index, record := range records {
			if index == 64 {
				lines = append(lines, field(label, fmt.Sprintf("… %d more records", len(records)-index)))
				break
			}
			lines = append(lines, field(fmt.Sprintf("%s %d", label, index+1), packetDNSRecord(record)))
		}
	}
	appendRecords("Answer", dns.Answers)
	appendRecords("Authority", dns.Authorities)
	appendRecords("Additional", dns.Additionals)
	return lines
}

func packetDNSRecord(record layers.DNSResourceRecord) string {
	value := ""
	switch record.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		value = record.IP.String()
	case layers.DNSTypeNS:
		value = string(record.NS)
	case layers.DNSTypeCNAME:
		value = string(record.CNAME)
	case layers.DNSTypePTR:
		value = string(record.PTR)
	case layers.DNSTypeTXT:
		texts := make([]string, 0, len(record.TXTs))
		for _, item := range record.TXTs {
			texts = append(texts, fmt.Sprintf("%q", safeUILine(string(item))))
		}
		value = strings.Join(texts, " ")
	default:
		value = fmt.Sprintf("%x", record.Data)
	}
	return fmt.Sprintf("%s  %s  %s  ttl=%d  %s", record.Name, record.Type, record.Class, record.TTL, value)
}
