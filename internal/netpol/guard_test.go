package netpol

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testGuard() GuardSpec {
	return GuardSpec{Organization: "org", Revision: "r1", ExpiresAt: time.Now().Add(time.Hour), DNS: []string{"*.example.com"}, Rules: []GuardRule{
		{ID: "https", Effect: "allow", CIDR: "0.0.0.0/0", Protocol: "tcp", Ports: []uint16{443}},
		{ID: "deny", Effect: "deny", CIDR: "8.8.8.8/32", Protocol: "any"},
	}}
}

func TestOrganizationGuardCannotBeOverridden(t *testing.T) {
	local := mustParse(t, `{"default":"allow","allowLocal":true,"rules":[{"action":"allow"}],"allowDomains":["*.example.com"]}`)
	guarded, err := WithGuard(local, testGuard())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip    string
		port  uint16
		allow bool
	}{
		{"1.1.1.1", 443, true}, {"1.1.1.1", 80, false}, {"8.8.8.8", 443, false}, {gatewayIP, 443, true}, {gatewayIP, 80, false},
	} {
		if got := guarded.MatchTX(ipFrame(t, tc.ip, protoTCP, tc.port, nil)); got != tc.allow {
			t.Errorf("%s:%d got %v", tc.ip, tc.port, got)
		}
	}
	// Local defaults, CIDR overrides and DNS-learned allowances cannot widen it.
	guarded.dynamic[[4]byte{1, 1, 1, 1}] = time.Now().Add(time.Hour)
	if guarded.Allows([4]byte{1, 1, 1, 1}, protoUDP, 443) {
		t.Fatal("DNS learning bypassed org guard")
	}
	raw, err := Marshal(guarded)
	if err != nil {
		t.Fatal(err)
	}
	clone, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := clone.Replace(DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	if clone.Allows([4]byte{8, 8, 8, 8}, protoTCP, 443) || clone.Allows([4]byte{1, 1, 1, 1}, protoTCP, 80) {
		t.Fatal("local default removed mandatory intersection")
	}
	if !clone.Allows([4]byte{1, 1, 1, 1}, protoTCP, 443) {
		t.Fatal("allowed flow lost on replacement")
	}
	if clone.DomainAllowed("evil.example") {
		t.Fatal("replacement dropped DNS guard")
	}
	if len(clone.RuleSummaries()) <= len(DefaultPolicy().RuleSummaries()) {
		t.Fatal("organization rules missing from inspection")
	}
	frame := ipFrame(t, "1.1.1.1", protoTCP, 443, nil)
	binary.BigEndian.PutUint16(frame[14+6:14+8], 0x2000)
	if clone.MatchTX(frame) {
		t.Fatal("governed fragment admitted without complete tuple")
	}
}

func TestOrganizationDNSIsResolutionOnly(t *testing.T) {
	guard := testGuard()
	guard.Rules = nil
	p, err := WithGuard(DefaultPolicy(), guard)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host    string
		allowed bool
	}{
		{"api.example.com.", true}, {"example.com.", true}, {"example.com.evil.", false},
	} {
		query := new(dns.Msg)
		query.SetQuestion(tc.host, dns.TypeA)
		raw, _ := query.Pack()
		if got := p.MatchTX(ipFrame(t, gatewayIP, protoUDP, 53, raw)); got != tc.allowed {
			t.Errorf("DNS %s: %v", tc.host, got)
		}
	}
	if p.Allows([4]byte{1, 1, 1, 1}, protoTCP, 443) {
		t.Fatal("DNS permissions granted IP access")
	}
	empty := testGuard()
	empty.DNS = nil
	p, err = WithGuard(DefaultPolicy(), empty)
	if err != nil {
		t.Fatal(err)
	}
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeTXT)
	raw, _ := query.Pack()
	if p.MatchTX(ipFrame(t, gatewayIP, protoUDP, 53, raw)) {
		t.Fatal("empty org DNS list must deny")
	}
}

func TestExpiredOrganizationGuardFailsClosed(t *testing.T) {
	spec := testGuard()
	spec.ExpiresAt = time.Now().Add(-time.Second)
	p, err := WithGuard(DefaultPolicy(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if p.MatchTX(ipFrame(t, "1.1.1.1", protoTCP, 443, nil)) || p.DomainAllowed("example.com") || p.AllowsGatewayUDPReplies() {
		t.Fatal("expired snapshot allowed access")
	}
}
