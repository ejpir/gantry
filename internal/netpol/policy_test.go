package netpol

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var guestMAC = [6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}
var gwMAC = [6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}

// ipFrame builds an Ethernet/IPv4 frame with a UDP or TCP stub payload.
func ipFrame(t *testing.T, dstIP string, proto uint8, dport uint16, payload []byte) []byte {
	return ipFrameFromPort(t, dstIP, proto, 12345, dport, payload)
}

func ipFrameFromPort(t *testing.T, dstIP string, proto uint8, sport, dport uint16, payload []byte) []byte {
	return ipFrameBetweenPorts(t, "192.168.127.2", dstIP, proto, sport, dport, payload)
}

func ipFrameBetweenPorts(t *testing.T, srcIP, dstIP string, proto uint8, sport, dport uint16, payload []byte) []byte {
	t.Helper()
	dst := net.ParseIP(dstIP).To4()
	src := net.ParseIP(srcIP).To4()
	if src == nil || dst == nil {
		t.Fatalf("invalid IPv4 endpoints %q -> %q", srcIP, dstIP)
	}
	var l4 []byte
	switch proto {
	case protoUDP:
		l4 = make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(l4[0:2], sport)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		binary.BigEndian.PutUint16(l4[4:6], uint16(8+len(payload)))
		copy(l4[8:], payload)
	case protoTCP:
		l4 = make([]byte, 20+len(payload))
		binary.BigEndian.PutUint16(l4[0:2], sport)
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
	if srcIP == gatewayIP {
		frame = append(frame, guestMAC[:]...)
		frame = append(frame, gwMAC[:]...)
	} else {
		frame = append(frame, gwMAC[:]...)
		frame = append(frame, guestMAC[:]...)
	}
	frame = append(frame, 0x08, 0x00)
	return append(append(frame, ip...), l4...)
}

func tcpFrameBetween(t *testing.T, srcIP, dstIP string, sport, dport uint16, flags byte, payload []byte) []byte {
	t.Helper()
	frame := ipFrameBetweenPorts(t, srcIP, dstIP, protoTCP, sport, dport, payload)
	frame[14+20+13] = flags
	return frame
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

func TestPolicyMayAllowLoopback(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want bool
	}{
		{name: "default local wall", raw: `{"default":"allow"}`, want: false},
		{name: "allow local", raw: `{"default":"deny","allowLocal":true}`, want: true},
		{name: "explicit loopback", raw: `{"default":"deny","rules":[{"action":"allow","cidr":"127.0.0.1/32","proto":"tcp","ports":"80"}]}`, want: true},
		{name: "allow all rule", raw: `{"default":"deny","rules":[{"action":"allow","proto":"tcp","ports":"443"}]}`, want: true},
		{name: "private only", raw: `{"default":"deny","rules":[{"action":"allow","cidr":"10.0.0.0/8"}]}`, want: false},
		{name: "loopback deny", raw: `{"default":"allow","rules":[{"action":"deny","cidr":"127.0.0.0/8"}]}`, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := mustParse(t, test.raw).MayAllowLoopback(); got != test.want {
				t.Fatalf("MayAllowLoopback() = %v, want %v", got, test.want)
			}
		})
	}
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

func TestWithoutDomainNormalizesAndRemovesAllowlistEntry(t *testing.T) {
	policy := mustParse(t, `{
		"default":"deny",
		"allowDomains":["example.com","api.github.com","example.com"]
	}`)
	next, err := WithoutDomain(policy, " Example.COM. ")
	if err != nil {
		t.Fatal(err)
	}
	if len(next.AllowDomains) != 1 || next.AllowDomains[0] != "api.github.com" {
		t.Fatalf("domains after removal = %v", next.AllowDomains)
	}
	if len(policy.AllowDomains) != 3 {
		t.Fatalf("source policy was mutated: %v", policy.AllowDomains)
	}
	if _, err := WithoutDomain(next, "missing.example"); err == nil {
		t.Fatal("missing domain removal succeeded")
	}
}

func TestWithDomainNormalizesAndDeduplicatesAllowlistEntry(t *testing.T) {
	policy := mustParse(t, `{"default":"deny","allowDomains":["api.github.com"]}`)
	next, err := WithDomain(policy, " Pi.DEV. ")
	if err != nil {
		t.Fatal(err)
	}
	next, err = WithDomain(next, "pi.dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(next.AllowDomains) != 2 || next.AllowDomains[1] != "pi.dev" {
		t.Fatalf("domains after additions = %v", next.AllowDomains)
	}
	if len(policy.AllowDomains) != 1 {
		t.Fatalf("source policy was mutated: %v", policy.AllowDomains)
	}
	query := ipFrame(t, gatewayIP, protoUDP, 53, dnsQuery(t, "pi.dev"))
	if policy.MatchTX(query) || !next.MatchTX(query) {
		t.Fatal("added domain did not change the DNS query decision")
	}
	if _, err := WithDomain(next, " . "); err == nil {
		t.Fatal("empty domain addition succeeded")
	}
}

func TestResolveDomainAllowsDNSWithoutLearningBroadPermission(t *testing.T) {
	policy := mustParse(t, `{"default":"deny","allowDomains":["api.example"]}`)
	next, err := WithResolveDomain(policy, " Proxy.Example. ")
	if err != nil {
		t.Fatal(err)
	}
	if len(next.ResolveDomains) != 1 || next.ResolveDomains[0] != "proxy.example" {
		t.Fatalf("resolve-only domains = %v", next.ResolveDomains)
	}
	if !next.MatchTX(ipFrame(t, gatewayIP, protoUDP, 53, dnsQuery(t, "proxy.example"))) {
		t.Fatal("resolve-only DNS query was blocked")
	}
	if next.MatchTX(ipFrame(t, gatewayIP, protoUDP, 53, dnsQuery(t, "other.example"))) {
		t.Fatal("unlisted DNS query was allowed")
	}
	answer := ipFrameBetweenPorts(t, gatewayIP, guestIP, protoUDP, 53, 12345,
		dnsAnswer(t, "proxy.example", "203.0.113.5"))
	next.ObserveRX(answer)
	if next.DynamicSize() != 0 {
		t.Fatal("resolve-only answer entered the dynamic allow table")
	}
	if next.Allows([4]byte{203, 0, 113, 5}, protoTCP, 443) {
		t.Fatal("resolve-only answer granted broad egress")
	}
	raw, err := Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(roundTrip.ResolveDomains) != 1 || roundTrip.ResolveDomains[0] != "proxy.example" {
		t.Fatalf("resolve-only domain lost in round trip: %s", raw)
	}
}

func TestPolicyReplaceAppliesToStableReceiver(t *testing.T) {
	stable := DefaultPolicy()
	public := [4]byte{8, 8, 8, 8}
	local := [4]byte{10, 0, 0, 1}
	if !stable.Allows(public, protoTCP, 443) {
		t.Fatal("default policy should allow public traffic")
	}
	if stable.Allows(local, protoTCP, 443) {
		t.Fatal("default policy should block local traffic")
	}

	deny := mustParse(t, `{"default":"deny","allowLocal":true}`)
	if err := stable.Replace(deny); err != nil {
		t.Fatal(err)
	}
	if stable.Allows(public, protoTCP, 443) {
		t.Fatal("stable receiver kept the old default after replacement")
	}
	if stable.Allows(local, protoTCP, 443) {
		t.Fatal("replacement's deny default should still deny local traffic")
	}
	if got := stable.Describe(); got != "default deny, local net allowed" {
		t.Fatalf("replacement description = %q", got)
	}

	allow := mustParse(t, `{"default":"allow","allowLocal":true}`)
	if err := stable.Replace(allow); err != nil {
		t.Fatal(err)
	}
	if !stable.Allows(public, protoTCP, 443) || !stable.Allows(local, protoTCP, 443) {
		t.Fatal("second replacement was not applied")
	}
	if err := stable.Replace(nil); err == nil {
		t.Fatal("nil replacement succeeded")
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
		{"dhcp allowed", ipFrameFromPort(t, "255.255.255.255", protoUDP, 68, 67, []byte{1}), true},
		{"subnet broadcast allowed (DHCP)", ipFrameFromPort(t, subnetBroadcast, protoUDP, 68, 67, []byte{1}), true},
		// regression: a unicast .255 address must NOT get the gateway pass
		{".255 unicast bypass denied", ipFrame(t, "8.8.8.255", protoTCP, 443, nil), true},
		{".255 unicast non-443 denied", ipFrame(t, "8.8.8.255", protoTCP, 80, nil), false},
		{".255 unicast udp denied", ipFrame(t, "52.1.2.255", protoUDP, 53, []byte{1}), false},
		{"gateway dns allowed (no allowlist)", ipFrame(t, gatewayIP, protoUDP, 53, []byte{1}), true},
		{"gateway other service denied", ipFrame(t, gatewayIP, protoTCP, 80, nil), false},
		{"gateway udp/68 is not DHCP", ipFrameFromPort(t, gatewayIP, protoUDP, 67, 68, []byte{1}), false},
		{"broadcast dns denied", ipFrame(t, "255.255.255.255", protoUDP, 53, []byte{1}), false},
		{"subnet broadcast tcp denied", ipFrame(t, subnetBroadcast, protoTCP, 80, nil), false},
		{"ipv6 dropped", append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x86, 0xdd}, make([]byte, 40)...), false},
	}
	for _, c := range cases {
		if got := p.MatchTX(c.frame); got != c.want {
			t.Errorf("%s: MatchTX = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPolicyRejectsGuestSourceSpoofing(t *testing.T) {
	p := mustParse(t, `{"default":"allow","allowLocal":true}`)
	for name, frame := range map[string][]byte{
		"gateway source":      ipFrameBetweenPorts(t, gatewayIP, "93.184.216.34", protoTCP, 12345, 443, nil),
		"public source":       ipFrameBetweenPorts(t, "203.0.113.9", "93.184.216.34", protoTCP, 12345, 443, nil),
		"zero source":         ipFrameBetweenPorts(t, "0.0.0.0", "93.184.216.34", protoUDP, 12345, 443, nil),
		"zero DHCP to public": ipFrameBetweenPorts(t, "0.0.0.0", "93.184.216.34", protoUDP, 68, 67, nil),
	} {
		if p.MatchTX(frame) {
			t.Errorf("%s was allowed on the fixed guest link", name)
		}
	}
	if !p.MatchTX(ipFrameBetweenPorts(t, "0.0.0.0", "255.255.255.255", protoUDP, 68, 67, []byte{1})) {
		t.Fatal("DHCP bootstrap request from 0.0.0.0 was denied")
	}
}

func TestPolicyGatewayRequiresExplicitLocalAccess(t *testing.T) {
	defaultPolicy := DefaultPolicy()
	for _, tc := range []struct {
		proto uint8
		port  uint16
	}{{protoTCP, 80}, {protoTCP, 2375}, {protoUDP, 123}} {
		if defaultPolicy.MatchTX(ipFrame(t, gatewayIP, tc.proto, tc.port, nil)) {
			t.Fatalf("default policy allowed gateway proto=%d port=%d", tc.proto, tc.port)
		}
	}

	explicit := mustParse(t, `{
		"default":"deny",
		"rules":[{"action":"allow","cidr":"192.168.127.1/32","proto":"tcp","ports":"80"}]
	}`)
	if !explicit.MatchTX(ipFrame(t, gatewayIP, protoTCP, 80, nil)) {
		t.Fatal("explicit gateway allow was ignored")
	}
	if explicit.MatchTX(ipFrame(t, gatewayIP, protoTCP, 2375, nil)) {
		t.Fatal("explicit gateway allow widened to another port")
	}

	allowLocalWithDeny := mustParse(t, `{
		"default":"allow",
		"allowLocal":true,
		"rules":[{"action":"deny","cidr":"192.168.127.1/32","proto":"tcp","ports":"80"}]
	}`)
	if allowLocalWithDeny.MatchTX(ipFrame(t, gatewayIP, protoTCP, 80, nil)) {
		t.Fatal("explicit gateway deny was bypassed")
	}
	if !allowLocalWithDeny.MatchTX(ipFrame(t, gatewayIP, protoTCP, 443, nil)) {
		t.Fatal("allowLocal did not permit an otherwise-unmatched gateway port")
	}
}

func TestAllowsGatewayUDPRepliesRequiresCompleteEffectiveRange(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "default local wall", raw: `{"default":"allow"}`},
		{name: "allow local default allow", raw: `{"default":"allow","allowLocal":true}`, want: true},
		{name: "allow local default deny", raw: `{"default":"deny","allowLocal":true}`},
		{
			name: "explicit complete range",
			raw:  `{"default":"deny","rules":[{"action":"allow","cidr":"192.168.127.1/32","proto":"udp","ports":"16000-65535"}]}`,
			want: true,
		},
		{
			name: "range misses final port",
			raw:  `{"default":"deny","rules":[{"action":"allow","cidr":"192.168.127.1/32","proto":"udp","ports":"16000-65534"}]}`,
		},
		{
			name: "earlier scoped deny wins",
			raw: `{"default":"deny","rules":[
				{"action":"deny","cidr":"192.168.127.1/32","proto":"udp","ports":"20000"},
				{"action":"allow","cidr":"192.168.127.1/32","proto":"udp","ports":"16000-65535"}
			]}`,
		},
		{
			name: "later deny loses to complete allow",
			raw: `{"default":"deny","rules":[
				{"action":"allow","cidr":"192.168.127.1/32","proto":"udp","ports":"16000-65535"},
				{"action":"deny","cidr":"192.168.127.1/32","proto":"udp","ports":"20000"}
			]}`,
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := mustParse(t, tc.raw)
			if got := policy.AllowsGatewayUDPReplies(); got != tc.want {
				t.Fatalf("AllowsGatewayUDPReplies() = %t, want %t", got, tc.want)
			}
			if err := ValidateUDPPortPublishing(policy); (err == nil) != tc.want {
				t.Fatalf("ValidateUDPPortPublishing() error = %v, want success %t", err, tc.want)
			}
		})
	}

	stable := DefaultPolicy()
	if stable.AllowsGatewayUDPReplies() {
		t.Fatal("default stable policy unexpectedly permits UDP replies")
	}
	if err := stable.Replace(mustParse(t, `{"default":"allow","allowLocal":true}`)); err != nil {
		t.Fatal(err)
	}
	if !stable.AllowsGatewayUDPReplies() {
		t.Fatal("UDP reply check did not follow policy replacement")
	}
	if err := ValidateUDPPortPublishing(nil); err == nil {
		t.Fatal("nil policy permitted UDP publishing")
	}
}

func TestPublishedTCPReturnFlowIsExactAndIngressInitiated(t *testing.T) {
	const (
		guestServicePort  = 18080
		gatewayClientPort = 49152
	)
	p := DefaultPolicy()
	returnFrame := tcpFrameBetween(t, guestIP, gatewayIP, guestServicePort, gatewayClientPort, tcpSYN|tcpACK, nil)
	if p.MatchTX(returnFrame) {
		t.Fatal("guest reached an arbitrary gateway port before trusted ingress")
	}

	// The embedded published-port forwarder dials from gatewayIP to the fixed
	// guest. Its initial SYN creates only the exact reverse-flow capability.
	p.ObserveRX(tcpFrameBetween(t, gatewayIP, guestIP, gatewayClientPort, guestServicePort, tcpSYN, nil))
	if !p.MatchTX(returnFrame) {
		t.Fatal("published TCP SYN-ACK return was denied")
	}
	// The forwarder's ACK is trusted ingress and promotes the pending tuple
	// before application data can flow.
	p.ObserveRX(tcpFrameBetween(t, gatewayIP, guestIP, gatewayClientPort, guestServicePort, tcpACK, nil))
	establishedReturn := tcpFrameBetween(t, guestIP, gatewayIP, guestServicePort, gatewayClientPort, tcpACK, []byte("HTTP/1.0 200 OK"))
	if !p.MatchTX(establishedReturn) {
		t.Fatal("established published TCP response was denied")
	}
	if err := p.Replace(mustParse(t, `{"default":"deny"}`)); err != nil {
		t.Fatal(err)
	}
	if !p.MatchTX(establishedReturn) {
		t.Fatal("policy replacement discarded established published flow")
	}
	denyExact := mustParse(t, `{"default":"allow","rules":[{"action":"deny","cidr":"192.168.127.1/32","proto":"tcp","ports":"49152"}]}`)
	if err := p.Replace(denyExact); err != nil {
		t.Fatal(err)
	}
	if p.MatchTX(establishedReturn) {
		t.Fatal("explicit gateway deny did not revoke established published flow")
	}
	if err := p.Replace(mustParse(t, `{"default":"deny"}`)); err != nil {
		t.Fatal(err)
	}
	if p.MatchTX(tcpFrameBetween(t, guestIP, gatewayIP, guestServicePort+1, gatewayClientPort, tcpACK, nil)) {
		t.Fatal("published flow widened to another guest source port")
	}
	if p.MatchTX(tcpFrameBetween(t, guestIP, gatewayIP, guestServicePort, gatewayClientPort+1, tcpACK, nil)) {
		t.Fatal("published flow widened to another gateway destination port")
	}
	if p.MatchTX(ipFrameBetweenPorts(t, guestIP, gatewayIP, protoUDP, guestServicePort, gatewayClientPort, nil)) {
		t.Fatal("published TCP flow widened to UDP")
	}
	for name, flags := range map[string]byte{
		"bare SYN": tcpSYN,
		"SYN|RST":  tcpSYN | tcpRST,
		"SYN|FIN":  tcpSYN | tcpFIN,
	} {
		if p.MatchTX(tcpFrameBetween(t, guestIP, gatewayIP, guestServicePort, gatewayClientPort, flags, nil)) {
			t.Fatalf("cached published flow admitted %s as a new gateway connection", name)
		}
	}
	fragmented := append([]byte(nil), establishedReturn...)
	binary.BigEndian.PutUint16(fragmented[14+6:14+8], 0x2000)
	if p.MatchTX(fragmented) {
		t.Fatal("fragmented packet consumed published-flow state")
	}
	malformed := append([]byte(nil), establishedReturn...)
	malformed[14+20+12] = 4 << 4
	if p.MatchTX(malformed) {
		t.Fatal("malformed TCP header consumed published-flow state")
	}

	rstPolicy := DefaultPolicy()
	rstPolicy.ObserveRX(tcpFrameBetween(t, gatewayIP, guestIP, gatewayClientPort, guestServicePort, tcpSYN, nil))
	if !rstPolicy.MatchTX(tcpFrameBetween(t, guestIP, gatewayIP, guestServicePort, gatewayClientPort, tcpRST, nil)) {
		t.Fatal("guest RST for pending published flow was denied")
	}
	if rstPolicy.MatchTX(returnFrame) {
		t.Fatal("guest RST did not delete published-flow state")
	}

	// A gateway SYN-ACK is a response to a guest-originated connection, not a
	// published connection initiator. Neither it nor a later ACK can create
	// return state without a prior tracked pure SYN.
	p2 := DefaultPolicy()
	p2.ObserveRX(tcpFrameBetween(t, gatewayIP, guestIP, gatewayClientPort, guestServicePort, tcpSYN|tcpACK, nil))
	p2.ObserveRX(tcpFrameBetween(t, gatewayIP, guestIP, gatewayClientPort, guestServicePort, tcpACK, nil))
	if p2.MatchTX(returnFrame) {
		t.Fatal("gateway SYN-ACK/ACK created published TCP return state")
	}
}

func TestGuestInitiatedGatewayFlowCannotSurvivePolicyTightening(t *testing.T) {
	const (
		guestClientPort    = 42000
		gatewayServicePort = 8080
	)
	permissive := DefaultPolicy()
	permissive.AllowLocal = true
	guestSYN := tcpFrameBetween(t, guestIP, gatewayIP, guestClientPort, gatewayServicePort, tcpSYN, nil)
	if !permissive.MatchTX(guestSYN) {
		t.Fatal("permissive policy unexpectedly denied guest-initiated gateway connection")
	}
	// A normal server-side handshake sends SYN-ACK followed by ACK/data. These
	// packets must never look like a gateway-originated published connection.
	permissive.ObserveRX(tcpFrameBetween(t, gatewayIP, guestIP, gatewayServicePort, guestClientPort, tcpSYN|tcpACK, nil))
	gatewayACK := tcpFrameBetween(t, gatewayIP, guestIP, gatewayServicePort, guestClientPort, tcpACK, nil)
	permissive.ObserveRX(gatewayACK)
	if err := permissive.Replace(DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	// In-flight ACK/data arriving after the restrictive swap cannot recreate
	// state either.
	permissive.ObserveRX(gatewayACK)
	guestACK := tcpFrameBetween(t, guestIP, gatewayIP, guestClientPort, gatewayServicePort, tcpACK, nil)
	if permissive.MatchTX(guestACK) {
		t.Fatal("guest-initiated gateway connection survived restrictive policy replacement")
	}
}

func TestGuestSwitchEchoCannotSeedPublishedFlow(t *testing.T) {
	const (
		guestClientPort    = 42001
		gatewayServicePort = 8080
	)
	permissive := mustParse(t, `{"default":"allow","allowLocal":true}`)
	// gvisor-tap-vsock's learning switch reflects a frame addressed to the
	// guest MAC back to the same QEMU link. Model that path exactly: only an
	// egress frame admitted by MatchTX can reappear at ObserveRX.
	echo := func(frame []byte) {
		if permissive.MatchTX(frame) {
			permissive.ObserveRX(frame)
		}
	}
	echo(tcpFrameBetween(t, gatewayIP, guestIP, gatewayServicePort, guestClientPort, tcpSYN, nil))
	echo(tcpFrameBetween(t, gatewayIP, guestIP, gatewayServicePort, guestClientPort, tcpACK, nil))
	if err := permissive.Replace(DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	guestACK := tcpFrameBetween(t, guestIP, gatewayIP, guestClientPort, gatewayServicePort, tcpACK, nil)
	if permissive.MatchTX(guestACK) {
		t.Fatal("self-reflected spoofed handshake poisoned published-flow state")
	}
}

func TestGuestSYNInvalidatesReusedPublishedTupleBeforePolicyAllow(t *testing.T) {
	const (
		guestPort   = 42002
		gatewayPort = 49155
	)
	p := DefaultPolicy()
	p.ObserveRX(tcpFrameBetween(t, gatewayIP, guestIP, gatewayPort, guestPort, tcpSYN, nil))
	p.ObserveRX(tcpFrameBetween(t, gatewayIP, guestIP, gatewayPort, guestPort, tcpACK, nil))
	guestACK := tcpFrameBetween(t, guestIP, gatewayIP, guestPort, gatewayPort, tcpACK, nil)
	if !p.MatchTX(guestACK) {
		t.Fatal("test setup did not establish a published return flow")
	}
	if err := p.Replace(mustParse(t, `{"default":"allow","allowLocal":true}`)); err != nil {
		t.Fatal(err)
	}

	// Frames that gVisor cannot treat as a new connection must not destroy
	// otherwise valid published state or pass via the permissive policy, even
	// when they carry a SYN bit.
	fragmentedSYN := tcpFrameBetween(t, guestIP, gatewayIP, guestPort, gatewayPort, tcpSYN, nil)
	binary.BigEndian.PutUint16(fragmentedSYN[14+6:14+8], 0x2000)
	if p.MatchTX(fragmentedSYN) {
		t.Fatal("fragmented gateway SYN was allowed")
	}
	malformedSYN := tcpFrameBetween(t, guestIP, gatewayIP, guestPort, gatewayPort, tcpSYN, nil)
	malformedSYN[14+20+12] = 4 << 4
	if p.MatchTX(malformedSYN) {
		t.Fatal("malformed gateway SYN was allowed")
	}
	if err := p.Replace(DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	if !p.MatchTX(guestACK) {
		t.Fatal("fragmented or malformed SYN deleted established published state")
	}

	if err := p.Replace(mustParse(t, `{"default":"allow","allowLocal":true}`)); err != nil {
		t.Fatal(err)
	}
	guestSYN := tcpFrameBetween(t, guestIP, gatewayIP, guestPort, gatewayPort, tcpSYN, nil)
	if !p.MatchTX(guestSYN) {
		t.Fatal("permissive policy unexpectedly denied tuple-reuse SYN")
	}
	// This is now a guest-initiated connection. Its normal gateway SYN-ACK and
	// ACK must not recreate the published capability invalidated above.
	p.ObserveRX(tcpFrameBetween(t, gatewayIP, guestIP, gatewayPort, guestPort, tcpSYN|tcpACK, nil))
	p.ObserveRX(tcpFrameBetween(t, gatewayIP, guestIP, gatewayPort, guestPort, tcpACK, nil))
	if err := p.Replace(DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	if p.MatchTX(guestACK) {
		t.Fatal("guest-initiated reuse of a stale published tuple survived policy tightening")
	}
}

func TestPublishedUDPIngressDoesNotCreatePacketOnlyException(t *testing.T) {
	const (
		guestServicePort  = 18081
		gatewayClientPort = 49153
	)
	p := DefaultPolicy()
	returnFrame := ipFrameBetweenPorts(t, guestIP, gatewayIP, protoUDP, guestServicePort, gatewayClientPort, []byte("reply"))
	if p.MatchTX(returnFrame) {
		t.Fatal("guest reached an arbitrary UDP gateway port before trusted ingress")
	}
	p.ObserveRX(ipFrameBetweenPorts(t, gatewayIP, guestIP, protoUDP, gatewayClientPort, guestServicePort, []byte("request")))
	if p.MatchTX(returnFrame) {
		t.Fatal("UDP ingress created a stale packet-only gateway capability")
	}
}

func TestPublishedReturnFlowExpiresAndTableIsBounded(t *testing.T) {
	const (
		guestServicePort  = 18082
		gatewayClientPort = 49154
	)
	p := DefaultPolicy()
	ingress := tcpFrameBetween(t, gatewayIP, guestIP, gatewayClientPort, guestServicePort, tcpSYN, nil)
	p.ObserveRX(ingress)
	returnFrame := tcpFrameBetween(t, guestIP, gatewayIP, guestServicePort, gatewayClientPort, tcpACK, nil)
	key, _, ok := publishedFlowFromReturn(mustParseFrame(t, returnFrame))
	if !ok {
		t.Fatal("test return frame did not produce a flow key")
	}
	table := p.publishedFlowTable()
	table.mu.Lock()
	initialExpiry := table.entries[key].Value.(*publishedFlowEntry).expiry
	table.mu.Unlock()
	pendingReturn := tcpFrameBetween(t, guestIP, gatewayIP, guestServicePort, gatewayClientPort, tcpSYN|tcpACK, nil)
	if !p.MatchTX(pendingReturn) {
		t.Fatal("pending published flow denied SYN-ACK")
	}
	table.mu.Lock()
	if got := table.entries[key].Value.(*publishedFlowEntry).expiry; !got.Equal(initialExpiry) {
		t.Fatalf("guest SYN-ACK refreshed pending expiry: got %v, want %v", got, initialExpiry)
	}
	table.mu.Unlock()
	p.ObserveRX(tcpFrameBetween(t, gatewayIP, guestIP, gatewayClientPort, guestServicePort, tcpACK, nil))
	table.mu.Lock()
	establishedExpiry := table.entries[key].Value.(*publishedFlowEntry).expiry
	table.mu.Unlock()
	if !p.MatchTX(returnFrame) {
		t.Fatal("established published flow denied ACK")
	}
	table.mu.Lock()
	if got := table.entries[key].Value.(*publishedFlowEntry).expiry; !got.Equal(establishedExpiry) {
		t.Fatalf("guest ACK refreshed established expiry: got %v, want %v", got, establishedExpiry)
	}
	table.entries[key].Value.(*publishedFlowEntry).expiry = time.Now().Add(-time.Second)
	table.mu.Unlock()
	if p.MatchTX(returnFrame) {
		t.Fatal("expired published flow remained usable")
	}
	trustedACK := tcpFrameBetween(t, gatewayIP, guestIP, gatewayClientPort, guestServicePort, tcpACK, nil)
	p.ObserveRX(trustedACK)
	if p.MatchTX(returnFrame) {
		t.Fatal("gateway ACK recreated expired flow without a tracked SYN")
	}
	// Establish it again so the capacity run below really evicts a live entry.
	p.ObserveRX(ingress)
	p.ObserveRX(trustedACK)
	if !p.MatchTX(returnFrame) {
		t.Fatal("new gateway SYN/ACK sequence did not re-establish flow")
	}

	base := time.Now()
	for i := 0; i <= maxPublishedFlows; i++ {
		frame := tcpFrameBetween(t, gatewayIP, guestIP, uint16(10000+i), guestServicePort, tcpSYN, nil)
		pp := mustParseFrame(t, frame)
		p.observePublishedIngress(pp, base.Add(time.Duration(i)*time.Nanosecond))
	}
	table.mu.Lock()
	size := len(table.entries)
	table.mu.Unlock()
	if size != maxPublishedFlows {
		t.Fatalf("published flow table size = %d, want bounded size %d", size, maxPublishedFlows)
	}
	table.mu.Lock()
	_, survivedEviction := table.entries[key]
	table.mu.Unlock()
	if survivedEviction {
		t.Fatal("least-recently-active established flow was not evicted at capacity")
	}
	p.ObserveRX(trustedACK)
	if p.MatchTX(returnFrame) {
		t.Fatal("gateway ACK recreated evicted flow without a tracked SYN")
	}
}

func TestPublishedFlowDNSFilteringTakesPrecedence(t *testing.T) {
	const guestServicePort = 18083
	p := mustParse(t, `{"default":"deny","allowDomains":["allowed.example"]}`)
	// Gateway service traffic cannot normally create conntrack state. Seed an
	// exact synthetic entry anyway to prove DNS filtering remains authoritative
	// even if state somehow survives from an older implementation or generation.
	flow := publishedFlow{
		guestIP: guestIPv4, gatewayIP: gatewayIPv4, proto: protoTCP,
		guestPort: guestServicePort, gatewayPort: 53,
	}
	table := p.publishedFlowTable()
	table.observe(flow, tcpSYN, time.Now())
	table.observe(flow, tcpACK, time.Now())
	evil := dnsQuery(t, "blocked.example")
	payload := append([]byte{byte(len(evil) >> 8), byte(len(evil))}, evil...)
	if p.MatchTX(tcpFrameBetween(t, guestIP, gatewayIP, guestServicePort, 53, tcpACK, payload)) {
		t.Fatal("published-flow state bypassed gateway DNS allowlist")
	}
}

func mustParseFrame(t *testing.T, frame []byte) parsedPacket {
	t.Helper()
	pp, arp, ok := parseFrame(frame)
	if arp || !ok {
		t.Fatal("test frame did not parse as IPv4")
	}
	return pp
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

	// Snoop a gateway response to an allowed question → IPs become reachable.
	frame := ipFrameBetweenPorts(t, gatewayIP, guestIP, protoUDP, 53, 12345,
		dnsAnswer(t, "deb.debian.org", "151.101.2.132"))
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
	f2 := ipFrameBetweenPorts(t, gatewayIP, guestIP, protoUDP, 53, 12345,
		dnsAnswer(t, "evil.com", "6.6.6.6"))
	p2.ObserveRX(f2)
	if p2.DynamicSize() != 0 {
		t.Fatal("unlisted answer leaked into the allow table")
	}
}

func TestGuestSwitchEchoCannotPoisonDNSAllowances(t *testing.T) {
	p := mustParse(t, `{"default":"deny","allowDomains":["allowed.example"]}`)
	poisoned := [4]byte{203, 0, 113, 66}
	forged := ipFrameBetweenPorts(t, guestIP, gatewayIP, protoUDP, 53, 53,
		dnsAnswer(t, "allowed.example", net.IP(poisoned[:]).String()))
	// The learning switch reflects unicast frames addressed to the guest MAC
	// onto this same link. MatchTX must reject a DNS response, and ObserveRX
	// must independently refuse to learn one that did not come from gatewayIP.
	copy(forged[0:6], guestMAC[:])
	if p.MatchTX(forged) {
		p.ObserveRX(forged)
		t.Fatal("outbound forged DNS response passed the query filter")
	}
	p.ObserveRX(forged)
	if p.DynamicSize() != 0 || p.Allows(poisoned, protoTCP, 443) {
		t.Fatal("self-reflected guest DNS response poisoned dynamic allowances")
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

func TestIsLocalIP(t *testing.T) {
	for _, test := range []struct {
		address string
		local   bool
	}{
		{address: "10.1.2.3", local: true},
		{address: "169.254.169.254", local: true},
		{address: "127.0.0.1", local: true},
		{address: "100.64.0.1", local: true},
		{address: "224.0.0.251", local: true},
		{address: "8.8.8.8", local: false},
		{address: "2001:4860:4860::8888", local: false},
	} {
		if got := IsLocalIP(net.ParseIP(test.address)); got != test.local {
			t.Errorf("IsLocalIP(%s) = %t, want %t", test.address, got, test.local)
		}
	}
}

func TestLocalWallBeatsDNSSnoop(t *testing.T) {
	// rebinding: an allowlisted domain resolving to a LAN IP must NOT
	// punch through the local wall
	p := mustParse(t, `{"default": "deny", "allowDomains": ["deb.debian.org"]}`)
	f := ipFrameBetweenPorts(t, gatewayIP, guestIP, protoUDP, 53, 12345,
		dnsAnswer(t, "deb.debian.org", "192.168.1.50"))
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

// The policy inspects single frames while the netstack reassembles: no piece
// of a fragmented or segmented DNS message may slip an unlisted name past
// the allowlist by being unparseable on its own.
func TestDomainAllowlistRejectsSplitAndFragmentedDNS(t *testing.T) {
	const evil = "exfiltrate-secret.evil.example"

	// DNS over TCP, one query split across two segments: neither segment is
	// a complete message, both must be dropped — and the guest's TCP will
	// wedge on retransmit, so the query can never reach the resolver.
	p := mustParse(t, `{"default": "deny", "allowDomains": ["deb.debian.org"]}`)
	q := dnsQuery(t, evil)
	prefixed := append([]byte{0, byte(len(q))}, q...)
	cut := len(prefixed) / 2
	for i, part := range [][]byte{prefixed[:cut], prefixed[cut:]} {
		if p.MatchTX(ipFrame(t, gatewayIP, protoTCP, 53, part)) {
			t.Fatalf("split TCP DNS segment %d was allowed", i+1)
		}
	}

	// Payload-less TCP control frames carry no DNS content: the handshake
	// itself must not be broken by fail-closed payload checks.
	if !p.MatchTX(ipFrame(t, gatewayIP, protoTCP, 53, nil)) {
		t.Fatal("TCP control frame (SYN/ACK) to the resolver should pass")
	}

	// A single segment must hold exactly ONE message: the stream length
	// prefix covering fewer bytes than the frame carries means pipelined
	// content (Unpack silently ignores trailing bytes) — reject.
	good := dnsQuery(t, "deb.debian.org")
	pipeline := append([]byte{0, byte(len(good))}, good...)
	pipeline = append(pipeline, 0, byte(len(q)))
	pipeline = append(pipeline, q...)
	if p.MatchTX(ipFrame(t, gatewayIP, protoTCP, 53, pipeline)) {
		t.Fatal("pipelined second DNS message bypassed the filter")
	}

	// IPv4 fragmentation: first fragment (MF, offset 0, ports present) and
	// non-first fragment (offset > 0, no ports) both fail closed.
	first := ipFrame(t, gatewayIP, protoUDP, 53, q[:8])
	binary.BigEndian.PutUint16(first[14+6:14+8], 0x2000) // MF set
	if p.MatchTX(first) {
		t.Fatal("first UDP DNS fragment was allowed")
	}
	second := ipFrame(t, gatewayIP, protoUDP, 53, q[8:])
	binary.BigEndian.PutUint16(second[14+6:14+8], 1) // fragment offset 8
	if p.MatchTX(second) {
		t.Fatal("non-first UDP DNS fragment was allowed")
	}

	// Without a domain allowlist, a non-first fragment still carries no port:
	// it cannot prove that it targets the resolver rather than a host-forwarded
	// gateway port, so it fails closed.
	open := mustParse(t, `{"default": "deny"}`)
	if open.MatchTX(second) {
		t.Fatal("unattributable gateway fragment bypassed the local wall")
	}

	// And the baseline still holds: a complete unlisted query is denied, a
	// complete allowlisted one passes.
	if p.MatchTX(ipFrame(t, gatewayIP, protoUDP, 53, q)) {
		t.Fatal("complete unlisted UDP query should be dropped")
	}
	if !p.MatchTX(ipFrame(t, gatewayIP, protoUDP, 53, good)) {
		t.Fatal("complete allowlisted UDP query should pass")
	}
}

// Non-initial fragments carry no ports, so a port-scoped deny could never
// match them — under a default-allow policy they used to slip through.
// MatchTX must fail closed on exactly that combination while leaving
// first fragments (which always carry the port pair) normally evaluated.
func TestDefaultAllowPortDenyDropsNonFirstFragments(t *testing.T) {
	p := mustParse(t, `{"default":"allow","rules":[{"action":"deny","proto":"tcp","ports":"443"}]}`)
	fragOff := func(f []byte) { binary.BigEndian.PutUint16(f[14+6:14+8], 1) } // offset 8
	mf := func(f []byte) { binary.BigEndian.PutUint16(f[14+6:14+8], 0x2000) }

	tail := ipFrame(t, "203.0.113.9", protoTCP, 443, []byte("data"))
	fragOff(tail)
	if p.MatchTX(tail) {
		t.Fatal("non-first fragment evaded the port-scoped deny")
	}

	first := ipFrame(t, "203.0.113.9", protoTCP, 443, nil)
	mf(first)
	if p.MatchTX(first) {
		t.Fatal("first fragment to a denied port should be dropped")
	}
	ok := ipFrame(t, "203.0.113.9", protoTCP, 80, nil)
	mf(ok)
	if !p.MatchTX(ok) {
		t.Fatal("first fragment to an allowed port should pass")
	}

	// No port-scoped deny anywhere: fragments keep the old behavior.
	open := mustParse(t, `{"default":"allow","rules":[{"action":"deny","cidr":"203.0.113.0/24"}]}`)
	tail2 := ipFrame(t, "198.51.100.7", protoTCP, 443, []byte("data"))
	fragOff(tail2)
	if !open.MatchTX(tail2) {
		t.Fatal("fragment dropped although no port-scoped deny exists")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	src := `{
		"default": "deny",
		"allowLocal": true,
		"rules": [
			{"action":"allow","cidr":"203.0.113.0/24","proto":"tcp","ports":"443,8000-9000"},
			{"action":"deny","cidr":"192.0.2.0/24"},
			{"action":"allow","proto":"udp","ports":"53"}
		],
		"allowDomains": ["Example.COM.", "api.github.com"]
	}`
	p1, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	raw1, err := Marshal(p1)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Parse(raw1)
	if err != nil {
		t.Fatalf("re-parse of marshaled policy: %v (%s)", err, raw1)
	}
	// Marshal is a fixpoint: marshal(parse(marshal(p))) == marshal(p)
	raw2, err := Marshal(p2)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw1) != string(raw2) {
		t.Fatalf("marshal not a fixpoint:\n%s\n%s", raw1, raw2)
	}
	// behavioral equality over a frame matrix
	for _, tc := range []struct {
		dst   string
		proto uint8
		port  uint16
	}{
		{"203.0.113.7", protoTCP, 443},
		{"203.0.113.7", protoTCP, 8443},
		{"203.0.113.7", protoTCP, 22},
		{"192.0.2.9", protoICMP, 0},
		{"198.51.100.4", protoTCP, 443},
		{"8.8.8.8", protoUDP, 53},
		{"10.0.0.8", protoTCP, 443},
	} {
		frame := ipFrame(t, tc.dst, tc.proto, tc.port, nil)
		if p1.MatchTX(frame) != p2.MatchTX(frame) {
			t.Fatalf("MatchTX mismatch %v: %v vs %v", tc, p1.MatchTX(frame), p2.MatchTX(frame))
		}
	}
	// default policy marshals into something that re-parses identically
	raw, err := Marshal(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(raw); err != nil {
		t.Fatalf("default policy round trip: %v (%s)", err, raw)
	}
}

func TestInteractiveRulesCoverAnyAndICMPProtocols(t *testing.T) {
	base := DefaultPolicy()
	denied, err := WithRule(base, RuleSpec{
		Action: "deny", CIDR: "203.0.113.9/32", Protocol: "any",
	})
	if err != nil {
		t.Fatal(err)
	}
	destination := [4]byte{203, 0, 113, 9}
	for _, protocol := range []uint8{protoICMP, protoTCP, protoUDP, 47} {
		if denied.Allows(destination, protocol, 443) {
			t.Errorf("any-protocol deny allowed IP protocol %d", protocol)
		}
	}

	allowed, err := WithRule(denied, RuleSpec{
		Action: "allow", CIDR: "203.0.113.9/32", Protocol: "icmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !allowed.Allows(destination, protoICMP, 0) {
		t.Fatal("ICMP override was not applied")
	}
	if allowed.Allows(destination, protoTCP, 443) {
		t.Fatal("ICMP override unexpectedly allowed TCP")
	}

	if _, err := WithRule(base, RuleSpec{Action: "deny", Protocol: "icmp", Ports: "53"}); err == nil {
		t.Fatal("port-scoped ICMP rule was accepted")
	}
}

func TestDomainAllowedFollowsReplace(t *testing.T) {
	p := DefaultPolicy()
	// No allowlist configured: the policy does not filter by name, matching
	// what the firewall does with a packet.
	if !p.DomainAllowed("github.com") {
		t.Fatal("default policy (no allowlist) should allow any name")
	}
	next, err := WithDomain(p, "*.github.com")
	if err != nil {
		t.Fatal(err)
	}
	if !next.DomainAllowed("api.github.com") || !next.DomainAllowed("github.com") {
		t.Fatal("wildcard should cover subdomains and the bare suffix")
	}
	if next.DomainAllowed("gitlab.com") {
		t.Fatal("unrelated domain unexpectedly allowed")
	}
	// A policy swap must be visible through the original handle: the broker
	// wires one Policy at boot and expects live updates.
	if err := p.Replace(next); err != nil {
		t.Fatal(err)
	}
	if !p.DomainAllowed("api.github.com") {
		t.Fatal("DomainAllowed did not follow Replace")
	}
}
