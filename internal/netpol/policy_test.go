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

func TestPolicyRuleSummaries(t *testing.T) {
	policy := mustParse(t, `{
		"default":"deny",
		"allowLocal":true,
		"rules":[{"action":"allow","cidr":"203.0.113.0/24","proto":"tcp","ports":"443,8000-8001"}],
		"allowDomains":["example.com"]
	}`)
	rules := policy.RuleSummaries()
	if len(rules) != 5 {
		t.Fatalf("summaries = %#v", rules)
	}
	if rules[0].Action != "deny" || rules[0].Protocol != "ether" {
		t.Fatalf("link summary = %#v", rules[0])
	}
	if rules[1].Action != "allow" || rules[1].Target != "203.0.113.0/24" || rules[1].Protocol != "tcp" || rules[1].Ports != "443,8000-8001" {
		t.Fatalf("explicit summary = %#v", rules[1])
	}
	if rules[2].Target != "example.com" || rules[3].Action != "allow" || rules[4].Action != "deny" {
		t.Fatalf("posture summaries = %#v", rules[2:])
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
		{"subnet broadcast allowed (DHCP)", ipFrame(t, subnetBroadcast, protoUDP, 67, []byte{1}), true},
		// regression: a unicast .255 address must NOT get the gateway pass
		{".255 unicast bypass denied", ipFrame(t, "8.8.8.255", protoTCP, 443, nil), true},
		{".255 unicast non-443 denied", ipFrame(t, "8.8.8.255", protoTCP, 80, nil), false},
		{".255 unicast udp denied", ipFrame(t, "52.1.2.255", protoUDP, 53, []byte{1}), false},
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

func TestLocalNetWall(t *testing.T) {
	// DefaultPolicy posture: internet yes, local net no
	p := DefaultPolicy()
	public := ipFrame(t, "93.184.216.34", protoTCP, 443, nil)
	if !p.MatchTX(public) {
		t.Fatal("public internet should be allowed by DefaultPolicy")
	}
	for name, dst := range map[string]string{
		"rfc1918/10":     "10.1.2.3",
		"rfc1918/172":    "172.16.5.4",
		"rfc1918/192":    "192.168.1.1",
		"host NAT alias": "192.168.127.254",
		"metadata":       "169.254.169.254",
		"link-local":     "169.254.1.1",
		"loopback":       "127.0.0.1",
		"cgnat":          "100.64.0.1",
		"multicast":      "224.0.0.251",
	} {
		if p.MatchTX(ipFrame(t, dst, protoTCP, 443, nil)) {
			t.Errorf("%s (%s) should be denied", name, dst)
		}
	}

	// allowLocal relaxes it
	p2 := DefaultPolicy()
	p2.AllowLocal = true
	if !p2.MatchTX(ipFrame(t, "192.168.1.1", protoTCP, 443, nil)) {
		t.Fatal("AllowLocal should permit LAN")
	}
	if !p2.MatchTX(ipFrame(t, "192.168.127.254", protoTCP, 445, nil)) {
		t.Fatal("AllowLocal should permit the host alias")
	}

	// explicit rule carves out one LAN subnet while the rest stays walled
	p3 := mustParse(t, `{"default": "allow", "rules": [
		{"action": "allow", "cidr": "10.9.0.0/16"}]}`)
	if !p3.MatchTX(ipFrame(t, "10.9.1.2", protoTCP, 22, nil)) {
		t.Fatal("explicit allow rule for a LAN subnet should win over the wall")
	}
	if p3.MatchTX(ipFrame(t, "10.8.1.2", protoTCP, 22, nil)) {
		t.Fatal("other LAN ranges must stay walled")
	}
	// and an explicit deny can wall a public IP even with default allow
	if p3.MatchTX(ipFrame(t, "93.184.216.34", protoTCP, 443, nil)) {
		// 93.184.216.34 not covered by any rule and not local: default allow
	} else {
		t.Fatal("public IP should still be allowed (default allow)")
	}
}

func TestLocalWallBeatsDNSSnoop(t *testing.T) {
	// rebinding: an allowlisted domain resolving to a LAN IP must NOT
	// punch through the local wall
	p := mustParse(t, `{"default": "deny", "allowDomains": ["deb.debian.org"]}`)
	f := ipFrame(t, "192.168.127.2", protoUDP, 12345, dnsAnswer(t, "deb.debian.org", "192.168.1.50"))
	binary.BigEndian.PutUint16(f[14+20:14+22], 53)
	p.ObserveRX(f)
	if p.DynamicSize() == 0 {
		t.Fatal("snoop should still record the answer")
	}
	var k [4]byte
	copy(k[:], net.ParseIP("192.168.1.50").To4())
	if p.Allows(k, protoTCP, 443) {
		t.Fatal("DNS-rebinded LAN IP must stay blocked by the wall")
	}

	// with allowLocal the same snooped IP is reachable
	p2 := mustParse(t, `{"default": "deny", "allowLocal": true, "allowDomains": ["deb.debian.org"]}`)
	p2.ObserveRX(f)
	if !p2.Allows(k, protoTCP, 443) {
		t.Fatal("allowLocal should admit snooped LAN IPs")
	}
}
