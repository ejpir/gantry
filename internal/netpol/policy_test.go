package netpol

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/miekg/dns"
)

var guestMAC = [6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}
var gwMAC = [6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}

// ipFrame builds an Ethernet/IPv4 frame with a UDP or TCP stub payload.
func ipFrame(t *testing.T, dstIP string, proto uint8, dport uint16, payload []byte) []byte {
	t.Helper()
	dst := net.ParseIP(dstIP).To4()
	src := net.ParseIP("192.168.127.2").To4()
	var l4 []byte
	switch proto {
	case protoUDP:
		l4 = make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(l4[0:2], 12345)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		binary.BigEndian.PutUint16(l4[4:6], uint16(8+len(payload)))
		copy(l4[8:], payload)
	case protoTCP:
		l4 = make([]byte, 20+len(payload))
		binary.BigEndian.PutUint16(l4[0:2], 12345)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		l4[12] = 5 << 4 // data offset
		copy(l4[20:], payload)
	case protoICMP:
		l4 = payload
	}
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(l4)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	frame := make([]byte, 0, 14+len(ip)+len(l4))
	frame = append(frame, gwMAC[:]...)
	frame = append(frame, guestMAC[:]...)
	frame = append(frame, 0x08, 0x00)
	return append(append(frame, ip...), l4...)
}

func arpFrame() []byte {
	f := make([]byte, 14+28)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], guestMAC[:])
	binary.BigEndian.PutUint16(f[12:14], etherTypeARP)
	return f
}

func mustParse(t *testing.T, js string) *Policy {
	t.Helper()
	p, err := Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPolicyParse(t *testing.T) {
	p := mustParse(t, `{
		"default": "deny",
		"rules": [
			{"action": "allow", "proto": "tcp", "ports": "443"},
			{"action": "allow", "cidr": "10.0.0.0/8", "proto": "udp", "ports": "53,8000-9000"},
			{"action": "deny", "cidr": "169.254.169.254/32"}
		],
		"allowDomains": ["deb.debian.org", "*.docker.io"]
	}`)
	if p.DefaultAllow {
		t.Fatal("default should be deny")
	}
	if len(p.Rules) != 3 || len(p.AllowDomains) != 2 {
		t.Fatalf("rules=%d domains=%d", len(p.Rules), len(p.AllowDomains))
	}
	if p.Rules[1].Ports[1] != (PortRange{8000, 9000}) {
		t.Fatalf("port range %+v", p.Rules[1].Ports)
	}

	for _, bad := range []string{
		`{"default": "maybe"}`,
		`{"rules": [{"action": "allow", "cidr": "nope"}]}`,
		`{"rules": [{"action": "allow", "proto": "sctp"}]}`,
		`{"rules": [{"action": "allow", "ports": "9000-8000"}]}`,
		`{"allowDomains": [""]}`,
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatalf("Parse(%s) succeeded, want error", bad)
		}
	}
}

func TestPolicyMatchTX(t *testing.T) {
	p := mustParse(t, `{
		"default": "deny",
		"rules": [
			{"action": "deny", "cidr": "169.254.169.254/32"},
			{"action": "allow", "proto": "tcp", "ports": "443"}
		]
	}`)

	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"arp always allowed", arpFrame(), true},
		{"tcp 443 allowed", ipFrame(t, "93.184.216.34", protoTCP, 443, nil), true},
		{"tcp 80 denied by default", ipFrame(t, "93.184.216.34", protoTCP, 80, nil), false},
		{"udp 443 denied (proto mismatch)", ipFrame(t, "93.184.216.34", protoUDP, 443, nil), false},
		{"metadata endpoint denied", ipFrame(t, "169.254.169.254", protoTCP, 443, nil), false},
		{"metadata on 80 denied", ipFrame(t, "169.254.169.254", protoTCP, 80, nil), false},
		{"icmp denied by default", ipFrame(t, "8.8.8.8", protoICMP, 0, []byte{8, 0, 0, 0}), false},
		{"dhcp allowed", ipFrame(t, "255.255.255.255", protoUDP, 67, []byte{1}), true},
		{"gateway dns allowed (no allowlist)", ipFrame(t, gatewayIP, protoUDP, 53, []byte{1}), true},
		{"gateway other svc allowed", ipFrame(t, gatewayIP, protoTCP, 80, nil), true},
		{"ipv6 dropped", append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x86, 0xdd}, make([]byte, 40)...), false},
	}
	for _, c := range cases {
		if got := p.MatchTX(c.frame); got != c.want {
			t.Errorf("%s: MatchTX = %v, want %v", c.name, got, c.want)
		}
	}
}

func dnsQuery(t *testing.T, name string) []byte {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeA)
	payload, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func dnsAnswer(t *testing.T, name string, ips ...string) []byte {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeA)
	msg.Response = true
	for _, ip := range ips {
		rr, err := dns.NewRR(dns.Fqdn(name) + " 300 IN A " + ip)
		if err != nil {
			t.Fatal(err)
		}
		msg.Answer = append(msg.Answer, rr)
	}
	payload, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestDomainAllowlistAndSnoop(t *testing.T) {
	p := mustParse(t, `{"default": "deny", "allowDomains": ["deb.debian.org", "*.docker.io"]}`)

	// DNS queries filtered by name
	if !p.MatchTX(ipFrame(t, gatewayIP, protoUDP, 53, dnsQuery(t, "deb.debian.org"))) {
		t.Fatal("allowed-domain query should pass")
	}
	if !p.MatchTX(ipFrame(t, gatewayIP, protoUDP, 53, dnsQuery(t, "auth.docker.io"))) {
		t.Fatal("wildcard sub-domain query should pass")
	}
	if !p.MatchTX(ipFrame(t, gatewayIP, protoUDP, 53, dnsQuery(t, "docker.io"))) {
		t.Fatal("wildcard should also match the bare suffix")
	}
	if p.MatchTX(ipFrame(t, gatewayIP, protoUDP, 53, dnsQuery(t, "evil.example.com"))) {
		t.Fatal("unlisted domain query should be dropped")
	}
	if p.MatchTX(ipFrame(t, gatewayIP, protoUDP, 53, dnsQuery(t, "docker.io.evil.com"))) {
		t.Fatal("suffix-spoof query should be dropped")
	}

	// nothing dynamic yet
	dst := net.ParseIP("151.101.2.132").To4()
	var k [4]byte
	copy(k[:], dst)
	if p.Allows(k, protoTCP, 443) {
		t.Fatal("no dynamic allowance before any DNS answer")
	}

	// snoop a response to an allowed question → IPs become reachable
	p.ObserveRX(ipFrame(t, "192.168.127.2", protoUDP, 12345,
		dnsAnswer(t, "deb.debian.org", "151.101.2.132", "151.101.66.132")))
	// fix source port to 53 (builds RX frame): rebuild with sport 53
	frame := ipFrame(t, "192.168.127.2", protoUDP, 12345, dnsAnswer(t, "deb.debian.org", "151.101.2.132"))
	binary.BigEndian.PutUint16(frame[14+20:14+22], 53)
	p.ObserveRX(frame)

	if p.DynamicSize() == 0 {
		t.Fatal("snoop did not learn any IPs")
	}
	if !p.Allows(k, protoTCP, 443) {
		t.Fatal("resolved IP should be allowed after snoop")
	}
	other := net.ParseIP("9.9.9.9").To4()
	copy(k[:], other)
	if p.Allows(k, protoTCP, 443) {
		t.Fatal("unresolved IP must stay denied")
	}

	// answers to unlisted questions teach nothing
	p2 := mustParse(t, `{"default": "deny", "allowDomains": ["only.this.org"]}`)
	f2 := ipFrame(t, "192.168.127.2", protoUDP, 12345, dnsAnswer(t, "evil.com", "6.6.6.6"))
	binary.BigEndian.PutUint16(f2[14+20:14+22], 53)
	p2.ObserveRX(f2)
	if p2.DynamicSize() != 0 {
		t.Fatal("unlisted answer leaked into the allow table")
	}
}

func TestDomainAllowlistTCPDNS(t *testing.T) {
	p := mustParse(t, `{"default": "deny", "allowDomains": ["deb.debian.org"]}`)
	q := dnsQuery(t, "deb.debian.org")
	// DNS over TCP carries a 2-byte length prefix
	payload := append([]byte{0, byte(len(q))}, q...)
	if !p.MatchTX(ipFrame(t, gatewayIP, protoTCP, 53, payload)) {
		t.Fatal("allowed TCP DNS query should pass")
	}
	q2 := dnsQuery(t, "nope.invalid")
	payload2 := append([]byte{0, byte(len(q2))}, q2...)
	if p.MatchTX(ipFrame(t, gatewayIP, protoTCP, 53, payload2)) {
		t.Fatal("unlisted TCP DNS query should be dropped")
	}
}
