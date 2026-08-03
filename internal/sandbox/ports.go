package sandbox

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"gantry/internal/vnet"
)

// PortMapping is one host→guest port forward. The zero HostPort means
// auto-assign; NormalizePortSpec resolves it to a concrete free port before
// the mapping is persisted or applied, so saved specs are always concrete.
type PortMapping struct {
	HostIP    string `json:"host_ip"`   // bind address; default 127.0.0.1 (never all-interfaces implicitly)
	HostPort  uint16 `json:"host_port"` // host listen port
	GuestPort uint16 `json:"guest_port"`
	Proto     string `json:"proto"` // "tcp" | "udp"
}

// ParsePortSpec accepts Docker's publish grammar:
//
//	8080:80              host 8080 (loopback) -> guest 80/tcp
//	127.0.0.1:8080:80    explicit bind address
//	[::1]:8080:80/udp    bracketed IPv6 + protocol
//	80                   auto-assigned host port -> guest 80
//
// Bind defaults to 127.0.0.1: a published port is a hole into the sandbox,
// so LAN exposure (-p 0.0.0.0:8080:80) must be written out explicitly.
func ParsePortSpec(spec string) (PortMapping, error) {
	m := PortMapping{HostIP: "127.0.0.1", Proto: "tcp"}
	s := strings.TrimSpace(spec)
	if s == "" {
		return m, fmt.Errorf("empty port spec")
	}
	if i := strings.LastIndex(s, "/"); i >= 0 {
		m.Proto = strings.ToLower(s[i+1:])
		s = s[:i]
		if m.Proto != "tcp" && m.Proto != "udp" {
			return m, fmt.Errorf("protocol must be tcp or udp, got %q", m.Proto)
		}
	}
	host := s
	if strings.HasPrefix(s, "[") { // [v6]:rest
		end := strings.Index(s, "]")
		if end < 0 {
			return m, fmt.Errorf("unterminated IPv6 bind address in %q", spec)
		}
		m.HostIP = s[1:end]
		host = strings.TrimPrefix(s[end+1:], ":")
	}
	parts := strings.Split(host, ":")
	ports := parts
	if len(parts) == 3 {
		m.HostIP = parts[0]
		ports = parts[1:]
	}
	switch len(ports) {
	case 1: // guestPort only
		m.GuestPort = parsePort(ports[0])
	case 2: // hostPort:guestPort
		m.HostPort = parsePort(ports[0])
		m.GuestPort = parsePort(ports[1])
	default:
		return m, fmt.Errorf("bad port spec %q: want [IP:]HOST:GUEST[/PROTO]", spec)
	}
	if m.GuestPort == 0 {
		return m, fmt.Errorf("bad port spec %q: guest port must be 1-65535", spec)
	}
	if parsePort(ports[0]) == 0 && len(ports) == 2 && ports[0] != "0" {
		return m, fmt.Errorf("bad port spec %q: host port must be 0-65535", spec)
	}
	if ip := net.ParseIP(m.HostIP); ip == nil {
		return m, fmt.Errorf("bad bind address %q", m.HostIP)
	}
	return m, nil
}

func parsePort(s string) uint16 {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

// String is the canonical storage form: IP:HOST:GUEST/PROTO (IPv6 bind
// bracketed, proto elided for tcp). Round-trips through ParsePortSpec.
func (m PortMapping) String() string {
	s := net.JoinHostPort(m.HostIP, strconv.Itoa(int(m.HostPort))) + ":" + strconv.Itoa(int(m.GuestPort))
	if m.Proto != "tcp" {
		s += "/" + m.Proto
	}
	return s
}

// Short is the compact display form: loopback and tcp elided
// ("8080→80", "0.0.0.0:8080→80/udp").
func (m PortMapping) Short() string {
	host := ""
	if m.HostIP != "127.0.0.1" {
		host = m.HostIP + ":"
	}
	s := fmt.Sprintf("%s%d→%d", host, m.HostPort, m.GuestPort)
	if m.Proto != "tcp" {
		s += "/" + m.Proto
	}
	return s
}

// Key dedupes mappings on the wire identity: proto + bind + host port.
func (m PortMapping) Key() string {
	return m.Proto + ":" + m.HostIP + ":" + strconv.Itoa(int(m.HostPort))
}

// Local is the netstack listen address ("127.0.0.1:8080").
func (m PortMapping) Local() string {
	return net.JoinHostPort(m.HostIP, strconv.Itoa(int(m.HostPort)))
}

// Remote is the in-stack dial target — the pinned guest IP + guest port.
func (m PortMapping) Remote() string {
	return net.JoinHostPort(vnet.GuestIP, strconv.Itoa(int(m.GuestPort)))
}

// NormalizePortSpec parses spec and, when the host port is 0, assigns a
// concrete free one, returning the canonical storage form. There is an
// inherent race between choosing a free port and the netstack binding it;
// on collision the boot/publish fails loudly, which is acceptable.
func NormalizePortSpec(spec string) (string, error) {
	m, err := ParsePortSpec(spec)
	if err != nil {
		return "", err
	}
	if m.HostPort == 0 {
		free, err := freePortForProto(m.Proto, m.bindAddr())
		if err != nil {
			return "", fmt.Errorf("auto-assign host port: %w", err)
		}
		m.HostPort = free
	}
	return m.String(), nil
}

// bindAddr is the address the auto-assign probe listens on: the requested
// bind IP when given, loopback otherwise. Probing 127.0.0.1 for a wildcard
// or LAN bind could hand out a port that is busy on another interface.
func (m PortMapping) bindAddr() string {
	if m.HostIP != "" {
		return m.HostIP
	}
	return "127.0.0.1"
}

func freePortForProto(proto, addr string) (uint16, error) {
	if proto == "udp" {
		pc, err := net.ListenPacket("udp", net.JoinHostPort(addr, "0"))
		if err != nil {
			return 0, err
		}
		defer pc.Close()
		return uint16(pc.LocalAddr().(*net.UDPAddr).Port), nil
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(addr, "0"))
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port), nil
}
