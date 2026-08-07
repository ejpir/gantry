// Package netpol enforces an egress network policy on sandbox traffic.
//
// Enforcement point: the virtio-net device's QEMU-framed link into the
// embedded netstack (internal/vnet). Every frame the guest emits — and every
// DNS answer it receives — crosses that link, so policy cannot be bypassed
// from inside the sandbox and works identically on every hypervisor backend.
//
// Two kinds of policy:
//
//   - L3/L4 rules: ordered allow/deny by destination CIDR, protocol, ports,
//     with a default action. Classic use: default-deny + allow tcp/443, or
//     deny the cloud metadata endpoint 169.254.169.254.
//   - Domain allowlist (allowDomains): DNS queries to the gateway resolver
//     are filtered by name; answers to allowed names are snooped and the
//     resolved IPs added to a dynamic allow table (TTL-capped). Classic
//     sandbox use: "only deb.debian.org and *.docker.io".
//
// Link-local services (ARP, DHCP, the gateway's DNS/service address) are
// always permitted so the network stays functional. A guest can still reach
// IPs it already knows without DNS (inherent to DNS-based filtering) — the
// rules layer is the hard guarantee, domains the convenient one.
package netpol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	etherTypeIPv4 = 0x0800
	etherTypeARP  = 0x0806
	etherTypeIPv6 = 0x86dd

	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17

	// gateway services that must stay reachable for the link to work
	gatewayIP = "192.168.127.1"
	// directed broadcast of the (fixed) guest subnet — must match
	// vnet.SubnetCIDR (192.168.127.0/24). Compared as an exact address:
	// a ".255" suffix match would hand the gateway-service pass to any
	// unicast address whose last octet is 255 (8.8.8.255, ...),
	// bypassing the rule list, the local-net wall and the default action.
	subnetBroadcast = "192.168.127.255"
	dnsMaxTTL       = 5 * time.Minute
	maxDynamic      = 4096
)

// Policy is the parsed, enforced form of the policy file.
type Policy struct {
	DefaultAllow bool     `json:"-"`
	Rules        []Rule   `json:"-"`
	AllowDomains []string `json:"-"` // normalized: lower-case, no trailing dot
	// AllowLocal permits destinations on the local network: RFC1918,
	// loopback, link-local (incl. the cloud metadata endpoint), CGNAT,
	// multicast, and the host itself (the .254 NAT alias). It is false by
	// default — including for DefaultPolicy — so sandboxes get internet
	// but cannot poke the LAN/host unless the owner opts in (flag or file).
	AllowLocal bool `json:"-"`

	// hasPortScopedDeny caches "any deny rule with a Ports list" so
	// MatchTX can fail closed on non-initial fragments (they carry no
	// ports and could otherwise never match such a rule).
	hasPortScopedDeny bool `json:"-"`

	mu      sync.Mutex
	dynamic map[[4]byte]time.Time // DNS-learned allowances: IPv4 -> expiry
	active  atomic.Pointer[Policy]
}

// Replace atomically switches every future policy decision to next. The
// stable receiver remains attached to the virtio-net device, so a running VM
// can change policy without rebuilding its device graph or network stack.
// DNS-learned allowances intentionally start empty in the replacement.
func (p *Policy) Replace(next *Policy) error {
	if p == nil || next == nil {
		return fmt.Errorf("network policy replacement is nil")
	}
	p.active.Store(next.current())
	return nil
}

func (p *Policy) current() *Policy {
	if p == nil {
		return nil
	}
	if current := p.active.Load(); current != nil {
		return current
	}
	return p
}

// localCIDRs is "the local network" the sandbox is walled off from unless
// AllowLocal (or an explicit rule covering them) says otherwise.
var localCIDRs = []*net.IPNet{
	mustCIDR("10.0.0.0/8"),     // RFC1918
	mustCIDR("172.16.0.0/12"),  // RFC1918
	mustCIDR("192.168.0.0/16"), // RFC1918 (incl. the host's .254 NAT alias)
	mustCIDR("169.254.0.0/16"), // link-local + cloud metadata 169.254.169.254
	mustCIDR("127.0.0.0/8"),    // loopback
	mustCIDR("100.64.0.0/10"),  // CGNAT (often LAN-adjacent)
	mustCIDR("224.0.0.0/4"),    // multicast (mDNS/SSDP LAN discovery)
	mustCIDR("240.0.0.0/4"),    // reserved; no business leaving a sandbox
	mustCIDR("0.0.0.0/8"),      // "this host" source block
}

func mustCIDR(s string) *net.IPNet {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return cidr
}

func isLocal(dst [4]byte) bool {
	ip := net.IP(dst[:])
	for _, c := range localCIDRs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

// DefaultPolicy is the posture when no policy file is supplied: the
// internet is reachable, the local network (LAN, link-local, the host's
// NAT alias) is not. Equivalent to {"default": "allow"} with AllowLocal
// left false — relax with the -allow-local-net flag or a policy file.
func DefaultPolicy() *Policy {
	return &Policy{DefaultAllow: true, dynamic: map[[4]byte]time.Time{}}
}

// Rule matches destination IP (CIDR, default all), protocol (tcp/udp/icmp,
// default all), and destination ports ("443", "53", "8000-9000"; default
// all). First matching rule wins.
type Rule struct {
	Deny  bool
	CIDR  *net.IPNet
	Proto uint8 // 0 = any
	Ports []PortRange
}

// PortRange is an inclusive [Lo, Hi] destination-port interval.
type PortRange struct{ Lo, Hi uint16 }

type fileRule struct {
	Action string `json:"action"` // "allow" (default) | "deny"
	CIDR   string `json:"cidr,omitempty"`
	Proto  string `json:"proto,omitempty"` // "tcp" | "udp" | "icmp"
	Ports  string `json:"ports,omitempty"` // "443" | "53,443" | "8000-9000"
}

type filePolicy struct {
	Default      string     `json:"default"` // "allow" (default) | "deny"
	AllowLocal   *bool      `json:"allowLocal,omitempty"`
	Rules        []fileRule `json:"rules"`
	AllowDomains []string   `json:"allowDomains"`
}

// Load parses a JSON policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses JSON policy text.
func Parse(data []byte) (*Policy, error) {
	var fp filePolicy
	if err := json.Unmarshal(data, &fp); err != nil {
		return nil, fmt.Errorf("network policy: %w", err)
	}
	p := &Policy{dynamic: map[[4]byte]time.Time{}}
	switch fp.Default {
	case "", "allow":
		p.DefaultAllow = true
	case "deny":
	default:
		return nil, fmt.Errorf("network policy: default must be \"allow\" or \"deny\", got %q", fp.Default)
	}
	for i, fr := range fp.Rules {
		r := Rule{}
		switch fr.Action {
		case "", "allow":
		case "deny":
			r.Deny = true
		default:
			return nil, fmt.Errorf("network policy: rule %d: bad action %q", i, fr.Action)
		}
		if fr.CIDR != "" {
			_, cidr, err := net.ParseCIDR(fr.CIDR)
			if err != nil {
				return nil, fmt.Errorf("network policy: rule %d: bad cidr: %w", i, err)
			}
			r.CIDR = cidr
		}
		switch fr.Proto {
		case "", "any":
		case "tcp":
			r.Proto = protoTCP
		case "udp":
			r.Proto = protoUDP
		case "icmp":
			r.Proto = protoICMP
		default:
			return nil, fmt.Errorf("network policy: rule %d: bad proto %q", i, fr.Proto)
		}
		if fr.Ports != "" {
			for _, spec := range strings.Split(fr.Ports, ",") {
				pr, err := parsePortRange(strings.TrimSpace(spec))
				if err != nil {
					return nil, fmt.Errorf("network policy: rule %d: %w", i, err)
				}
				r.Ports = append(r.Ports, pr)
			}
		}
		p.Rules = append(p.Rules, r)
		if r.Deny && len(r.Ports) > 0 {
			p.hasPortScopedDeny = true
		}
	}
	if fp.AllowLocal != nil {
		p.AllowLocal = *fp.AllowLocal
	}
	for _, d := range fp.AllowDomains {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d == "" {
			return nil, fmt.Errorf("network policy: empty domain in allowDomains")
		}
		p.AllowDomains = append(p.AllowDomains, d)
	}
	return p, nil
}

func parsePortRange(spec string) (PortRange, error) {
	lo, hi := spec, spec
	if i := strings.IndexByte(spec, '-'); i >= 0 {
		lo, hi = spec[:i], spec[i+1:]
	}
	l, err := strconv.ParseUint(lo, 10, 16)
	if err != nil {
		return PortRange{}, fmt.Errorf("bad port %q", spec)
	}
	h, err := strconv.ParseUint(hi, 10, 16)
	if err != nil || h < l {
		return PortRange{}, fmt.Errorf("bad port range %q", spec)
	}
	return PortRange{uint16(l), uint16(h)}, nil
}

// RuleSummary is a stable, presentation-friendly view used by the dashboard.
type RuleSummary struct {
	Action   string `json:"action"`
	Target   string `json:"target"`
	Protocol string `json:"protocol"`
	Ports    string `json:"ports,omitempty"`
	Source   string `json:"source"`
}

// RuleSummaries returns explicit rules in evaluation order followed by the
// domain allowlist, local-network posture and default internet action.
func (p *Policy) RuleSummaries() []RuleSummary {
	if current := p.current(); current != p {
		return current.RuleSummaries()
	}
	if p == nil {
		return nil
	}
	out := make([]RuleSummary, 0, len(p.Rules)+len(p.AllowDomains)+3)
	out = append(out, RuleSummary{
		Action: "deny", Target: "IPv6 and non-IPv4 traffic", Protocol: "ether", Source: "built-in",
	})
	for i, rule := range p.Rules {
		action := "allow"
		if rule.Deny {
			action = "deny"
		}
		target := "all destinations"
		if rule.CIDR != nil {
			target = rule.CIDR.String()
		}
		var ports []string
		for _, portRange := range rule.Ports {
			if portRange.Lo == portRange.Hi {
				ports = append(ports, strconv.Itoa(int(portRange.Lo)))
			} else {
				ports = append(ports, fmt.Sprintf("%d-%d", portRange.Lo, portRange.Hi))
			}
		}
		out = append(out, RuleSummary{
			Action: action, Target: target, Protocol: protocolLabel(rule.Proto),
			Ports: strings.Join(ports, ","), Source: fmt.Sprintf("rule %d", i+1),
		})
	}
	for _, domain := range p.AllowDomains {
		out = append(out, RuleSummary{Action: "allow", Target: domain, Protocol: "dns", Source: "domain"})
	}
	localAction := "deny"
	if p.AllowLocal {
		localAction = "allow"
	}
	out = append(out, RuleSummary{Action: localAction, Target: "local networks", Protocol: "any", Source: "built-in"})
	defaultAction := "deny"
	if p.DefaultAllow {
		defaultAction = "allow"
	}
	out = append(out, RuleSummary{Action: defaultAction, Target: "public internet", Protocol: "any", Source: "default"})
	return out
}

func protocolLabel(protocol uint8) string {
	switch protocol {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	case protoICMP:
		return "icmp"
	default:
		return "any"
	}
}

// Describe summarizes the policy for startup logs.
func (p *Policy) Describe() string {
	if current := p.current(); current != p {
		return current.Describe()
	}
	def := "deny"
	if p.DefaultAllow {
		def = "allow"
	}
	s := fmt.Sprintf("default %s", def)
	if p.AllowLocal {
		s += ", local net allowed"
	} else {
		s += ", local net denied"
	}
	if len(p.Rules) > 0 {
		s += fmt.Sprintf(", %d rules", len(p.Rules))
	}
	if len(p.AllowDomains) > 0 {
		s += fmt.Sprintf(", domains: %s", strings.Join(p.AllowDomains, ", "))
	}
	return s
}

// ---------------------------------------------------------------------------
// frame inspection

type parsedPacket struct {
	src        [4]byte
	dst        [4]byte
	proto      uint8
	sport      uint16
	dport      uint16
	l4         []byte // transport header (for DNS parsing)
	isUDP      bool
	srcIsDNS   bool // RX: source port 53
	fragmented bool // IPv4: more-fragments bit set or non-zero fragment offset
}

// parseFrame extracts what policy needs from an Ethernet frame. ok=false
// means "not an IPv4 packet policy applies to": ARP returns arp=true; other
// ethertypes (IPv6 included) return arp=false, ok=false.
func parseFrame(frame []byte) (pp parsedPacket, arp, ok bool) {
	if len(frame) < 14+20 {
		return pp, false, false
	}
	et := binary.BigEndian.Uint16(frame[12:14])
	if et == etherTypeARP {
		return pp, true, false
	}
	if et != etherTypeIPv4 {
		return pp, false, false
	}
	ip := frame[14:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl || ip[0]>>4 != 4 {
		return pp, false, false
	}
	pp.proto = ip[9]
	copy(pp.src[:], ip[12:16])
	copy(pp.dst[:], ip[16:20])
	// Fragmented non-first fragments carry no ports (dport stays 0), so a
	// rule with a Ports list can't match them; MatchTX drops them
	// fail-closed when the policy is default-allow with port-scoped
	// denies. Under the far more common default-deny they fail closed on
	// their own. Reassembly still needs the first fragment, which is
	// port-evaluated as usual (IPv4's minimum non-final fragment payload
	// is 8 bytes, so the port pair always parses there).
	frag := binary.BigEndian.Uint16(ip[6:8])
	off := int(frag&0x1fff) * 8
	pp.fragmented = frag&0x3fff != 0 // MF (0x2000) or any fragment offset
	pp.l4 = ip[ihl:]
	if off == 0 && len(pp.l4) >= 4 {
		pp.sport = binary.BigEndian.Uint16(pp.l4[0:2])
		pp.dport = binary.BigEndian.Uint16(pp.l4[2:4])
		pp.isUDP = pp.proto == protoUDP
		pp.srcIsDNS = pp.sport == 53
	}
	return pp, false, true
}

// MatchTX decides whether an egress frame from the guest may proceed.
func (p *Policy) MatchTX(frame []byte) bool {
	if current := p.current(); current != p {
		return current.MatchTX(frame)
	}
	pp, arp, ok := parseFrame(frame)
	if arp {
		return true // link-local name resolution, harmless
	}
	if !ok {
		return false // policy active: no IPv6, no exotic ethertypes
	}
	// Close the fragmentation gap documented in parseFrame: a non-initial
	// fragment (no ports parsed) can never match a port-scoped deny and
	// would fall through to the default-allow verdict — drop it instead.
	if pp.fragmented && pp.sport == 0 && pp.dport == 0 && p.DefaultAllow && p.hasPortScopedDeny {
		return false
	}
	dst := net.IP(pp.dst[:])
	// Only the sandbox's own gateway and broadcast (DHCP) get the
	// link-services pass; multicast is NOT exempt — mDNS/SSDP probes are
	// LAN discovery and belong behind the local-network wall.
	if dst.Equal(net.ParseIP(gatewayIP)) ||
		dst.Equal(net.IPv4bcast) || dst.Equal(net.ParseIP(subnetBroadcast)) {
		return p.matchGatewayService(pp)
	}
	return p.Allows(pp.dst, pp.proto, pp.dport)
}

// matchGatewayService keeps the link functional: DHCP always, DNS filtered
// by name when a domain allowlist exists, everything else to the gateway
// address (its captive services) allowed.
func (p *Policy) matchGatewayService(pp parsedPacket) bool {
	if pp.proto == protoUDP && (pp.dport == 67 || pp.dport == 68) {
		return true // DHCP
	}
	// Policy inspects single frames; the netstack reassembles. Under a
	// domain allowlist no single frame of a fragmented datagram can be
	// attributed to a query name — and non-first fragments carry no ports
	// at all — so fail closed or split queries walk around the filter.
	if pp.fragmented && len(p.AllowDomains) > 0 && (pp.proto == protoUDP || pp.proto == protoTCP) {
		return false
	}
	if (pp.proto == protoUDP || pp.proto == protoTCP) && pp.dport == 53 && len(p.AllowDomains) > 0 {
		return p.dnsQueryAllowed(pp)
	}
	return true
}

// dnsQueryAllowed permits only DNS queries whose name matches the allowlist
// (also blocking TXT-record exfiltration of unlisted names).
//
// Everything unparseable fails CLOSED: an incomplete message in a single
// frame (TCP segmentation, truncation) must not pass the name filter. The
// one exception is a TCP frame with no transport payload at all — SYN/ACK/
// FIN/keepalive — which carries no DNS content; every DATA-bearing frame
// must hold exactly one complete, allowlisted message (the stream framing
// length must cover the whole segment, so pipelined messages and trailing
// bytes — which dns.Msg.Unpack would silently ignore — are rejected too).
func (p *Policy) dnsQueryAllowed(pp parsedPacket) bool {
	payload, hasData := dnsPayload(pp)
	if !hasData {
		return true // TCP control frame: no DNS content to judge
	}
	if payload == nil {
		return false // incomplete/truncated: must not bypass the filter
	}
	if pp.proto == protoTCP {
		off := int(pp.l4[12]>>4) * 4
		if int(binary.BigEndian.Uint16(pp.l4[off:off+2])) != len(payload) {
			return false // partial or pipelined stream content
		}
	}
	var msg dns.Msg
	if err := msg.Unpack(payload); err != nil || len(msg.Question) == 0 {
		return false
	}
	for _, q := range msg.Question {
		if !p.domainAllowed(q.Name) {
			return false
		}
	}
	return true
}

// dnsPayload returns the DNS payload of the frame and whether the frame
// carries any transport payload at all (false only for payload-less TCP
// control frames).
func dnsPayload(pp parsedPacket) ([]byte, bool) {
	if pp.proto == protoUDP {
		if len(pp.l4) < 8 {
			return nil, true // truncated datagram: unreadable data
		}
		return pp.l4[8:], true
	}
	if pp.proto == protoTCP && len(pp.l4) >= 13 {
		off := int(pp.l4[12]>>4) * 4
		if off < 20 || len(pp.l4) < off {
			return nil, true // malformed TCP header
		}
		if len(pp.l4) == off {
			return nil, false // pure control: SYN/ACK/FIN/keepalive
		}
		// DNS over TCP: 2-byte length prefix, then the message.
		if len(pp.l4) >= off+2 {
			return pp.l4[off+2:], true
		}
		return nil, true // lone prefix byte: incomplete message
	}
	return nil, true
}

// Allows reports whether traffic to dst/proto/dport is permitted, in
// order: explicit rules (they can carve LAN subnets in or public IPs out),
// then the local-network wall, then DNS-learned allowances, then the
// default. The wall sits BEFORE the dynamic table on purpose: an
// allowlisted domain that resolves to a local address (DNS rebinding) is
// still blocked unless local access was explicitly granted.
func (p *Policy) Allows(dst [4]byte, proto uint8, dport uint16) bool {
	if current := p.current(); current != p {
		return current.Allows(dst, proto, dport)
	}
	dstIP := net.IP(dst[:])
	for _, r := range p.Rules {
		if r.CIDR != nil && !r.CIDR.Contains(dstIP) {
			continue
		}
		if r.Proto != 0 && r.Proto != proto {
			continue
		}
		if len(r.Ports) > 0 {
			match := false
			for _, pr := range r.Ports {
				if dport >= pr.Lo && dport <= pr.Hi {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		return !r.Deny
	}
	if !p.AllowLocal && isLocal(dst) {
		return false
	}
	p.mu.Lock()
	if exp, ok := p.dynamic[dst]; ok {
		if time.Now().Before(exp) {
			p.mu.Unlock()
			return true
		}
		delete(p.dynamic, dst)
	}
	p.mu.Unlock()
	return p.DefaultAllow
}

// ObserveRX snoops DNS answers flowing back to the guest: A/AAAA records of
// responses to allowlisted questions become dynamic allowances. (AAAA IPs
// are recorded but moot — the embedded netstack is IPv4-only today.)
func (p *Policy) ObserveRX(frame []byte) {
	if current := p.current(); current != p {
		current.ObserveRX(frame)
		return
	}
	if len(p.AllowDomains) == 0 {
		return
	}
	pp, _, ok := parseFrame(frame)
	if !ok || !pp.srcIsDNS {
		return
	}
	payload, _ := dnsPayload(pp)
	if payload == nil {
		return
	}
	var msg dns.Msg
	if err := msg.Unpack(payload); err != nil || !msg.Response {
		return
	}
	allowed := false
	for _, q := range msg.Question {
		if p.domainAllowed(q.Name) {
			allowed = true
			break
		}
	}
	if !allowed {
		return
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, rr := range msg.Answer {
		var ip net.IP
		var ttl time.Duration
		switch r := rr.(type) {
		case *dns.A:
			ip, ttl = r.A, time.Duration(r.Hdr.Ttl)*time.Second
		default:
			continue
		}
		if ttl > dnsMaxTTL {
			ttl = dnsMaxTTL
		}
		if ttl == 0 {
			ttl = time.Minute
		}
		if v4 := ip.To4(); v4 != nil && len(p.dynamic) < maxDynamic {
			var k [4]byte
			copy(k[:], v4)
			p.dynamic[k] = now.Add(ttl)
		}
	}
}

// DynamicSize exposes the learned-allowance table size (for tests/logs).
func (p *Policy) DynamicSize() int {
	if current := p.current(); current != p {
		return current.DynamicSize()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.dynamic)
}

// domainAllowed matches exact names and "*.suffix" patterns; a wildcard
// also matches the bare suffix ("*.docker.io" ⊇ "docker.io").
func (p *Policy) domainAllowed(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, d := range p.AllowDomains {
		if strings.HasPrefix(d, "*.") {
			suf := d[2:]
			if name == suf || strings.HasSuffix(name, "."+suf) {
				return true
			}
		} else if name == d {
			return true
		}
	}
	return false
}

// Summarize describes a frame's destination for drop logging:
// "tcp 10.1.2.3:443", "udp 192.168.1.1:53", "icmp 8.8.8.8", ...
func Summarize(frame []byte) string {
	pp, arp, ok := parseFrame(frame)
	if arp {
		return "arp"
	}
	if !ok {
		return "non-ipv4"
	}
	proto := "ip"
	switch pp.proto {
	case protoTCP:
		proto = "tcp"
	case protoUDP:
		proto = "udp"
	case protoICMP:
		proto = "icmp"
	}
	if pp.proto == protoTCP || pp.proto == protoUDP {
		return fmt.Sprintf("%s %s:%d", proto, net.IP(pp.dst[:]), pp.dport)
	}
	return fmt.Sprintf("%s %s", proto, net.IP(pp.dst[:]))
}
