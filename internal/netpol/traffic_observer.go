package netpol

import (
	"encoding/binary"
	"net"
	"time"
)

const (
	trafficDHCPServerPort = 67
	trafficDHCPClientPort = 68
	trafficDNSPort        = 53
	trafficICMPv6Protocol = 58

	ethernetHeaderSize    = 14
	etherTypeOffset       = 12
	etherTypeSize         = 2
	ipv6HeaderSize        = 40
	ipv6Version           = 6
	ipv6NextHeaderOffset  = 6
	ipv6SourceOffset      = 8
	ipv6DestinationOffset = 24
	ipv6AddressSize       = 16
	transportPortSize     = 2
)

type trafficDirection uint8

const (
	trafficOutbound trafficDirection = iota
	trafficInbound
)

type inspectedTrafficFrame struct {
	raw    []byte
	packet parsedPacket
	arp    bool
	parsed bool
}

type trafficObservation struct {
	host     string
	address  string
	protocol string
	port     uint16
	allowed  bool
}

func inspectTrafficFrame(frame []byte) inspectedTrafficFrame {
	packet, arp, parsed := parseFrame(frame)
	return inspectedTrafficFrame{raw: frame, packet: packet, arp: arp, parsed: parsed}
}

func classifyTrafficObservation(frame inspectedTrafficFrame, direction trafficDirection, allowed bool, names *trafficDNSCache, now time.Time) (trafficObservation, bool) {
	if frame.arp {
		return trafficObservation{}, false
	}
	if !frame.parsed {
		return nonIPv4TrafficObservation(frame.raw, direction, allowed), true
	}
	packet := frame.packet
	if isDHCP(packet.proto, packet.sport, packet.dport) {
		return trafficObservation{}, false
	}
	if direction == trafficOutbound {
		return outboundIPv4Observation(packet, allowed, names, now), true
	}
	return inboundIPv4Observation(packet, names, now), true
}

func nonIPv4TrafficObservation(frame []byte, direction trafficDirection, allowed bool) trafficObservation {
	address, protocol, port := trafficIPv6Endpoint(frame, direction)
	if address == "" {
		address, protocol = "non-ipv4", "ether"
	}
	return newTrafficObservation(address, address, protocol, port, allowed)
}

func outboundIPv4Observation(packet parsedPacket, allowed bool, names *trafficDNSCache, now time.Time) trafficObservation {
	address := net.IP(packet.dst[:]).String()
	if isDNSRequest(packet) {
		host := dnsQuestionHost(packet)
		if host == "" {
			host = address
		}
		return newDNSTrafficObservation(host, address, allowed)
	}
	host := names.lookup(packet.dst, now)
	if host == "" {
		host = address
	}
	return newTrafficObservation(address, host, protocolName(packet.proto), packet.dport, allowed)
}

func inboundIPv4Observation(packet parsedPacket, names *trafficDNSCache, now time.Time) trafficObservation {
	address := net.IP(packet.src[:]).String()
	if packet.srcIsDNS {
		host := names.observeResponse(packet, now)
		if host != "" {
			return newDNSTrafficObservation(host, address, true)
		}
	}
	host := names.lookup(packet.src, now)
	if host == "" {
		host = address
	}
	return newTrafficObservation(address, host, protocolName(packet.proto), packet.sport, true)
}

func newTrafficObservation(address, host, protocol string, port uint16, allowed bool) trafficObservation {
	return trafficObservation{
		host:     host,
		address:  address,
		protocol: protocol,
		port:     port,
		allowed:  allowed,
	}
}

func newDNSTrafficObservation(host, address string, allowed bool) trafficObservation {
	return newTrafficObservation(address, host, "dns", trafficDNSPort, allowed)
}

func isDNSRequest(packet parsedPacket) bool {
	return (packet.proto == protoUDP || packet.proto == protoTCP) && packet.dport == trafficDNSPort
}

func isDHCP(protocol uint8, sourcePort, destinationPort uint16) bool {
	if protocol != protoUDP {
		return false
	}
	return isDHCPPort(sourcePort) || isDHCPPort(destinationPort)
}

func isDHCPPort(port uint16) bool {
	return port == trafficDHCPServerPort || port == trafficDHCPClientPort
}

func trafficIPv6Endpoint(frame []byte, direction trafficDirection) (address, protocol string, port uint16) {
	if !isIPv6Frame(frame) {
		return "", "", 0
	}
	ip := frame[ethernetHeaderSize : ethernetHeaderSize+ipv6HeaderSize]
	nextHeader := ip[ipv6NextHeaderOffset]
	peerOffset, portOffset := ipv6PeerOffsets(direction)
	peer := ip[peerOffset : peerOffset+ipv6AddressSize]
	protocol = ipv6ProtocolName(nextHeader)
	transport := frame[ethernetHeaderSize+ipv6HeaderSize:]
	if hasTransportPorts(nextHeader, transport) {
		port = binary.BigEndian.Uint16(transport[portOffset : portOffset+transportPortSize])
	}
	return net.IP(peer).String(), protocol, port
}

func isIPv6Frame(frame []byte) bool {
	if len(frame) < ethernetHeaderSize+ipv6HeaderSize {
		return false
	}
	etherType := binary.BigEndian.Uint16(frame[etherTypeOffset : etherTypeOffset+etherTypeSize])
	return etherType == etherTypeIPv6 && frame[ethernetHeaderSize]>>4 == ipv6Version
}

func ipv6PeerOffsets(direction trafficDirection) (peer, port int) {
	if direction == trafficOutbound {
		return ipv6DestinationOffset, transportPortSize
	}
	return ipv6SourceOffset, 0
}

func hasTransportPorts(protocol uint8, transport []byte) bool {
	return (protocol == protoTCP || protocol == protoUDP) && len(transport) >= 2*transportPortSize
}

func ipv6ProtocolName(protocol uint8) string {
	switch protocol {
	case protoTCP:
		return "tcp6"
	case protoUDP:
		return "udp6"
	case trafficICMPv6Protocol:
		return "icmp6"
	default:
		return "ipv6"
	}
}

func protocolName(protocol uint8) string {
	switch protocol {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	case protoICMP:
		return "icmp"
	default:
		return "ip"
	}
}
