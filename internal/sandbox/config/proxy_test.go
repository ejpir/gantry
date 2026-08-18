package config

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/netpol"
)

type staticProxyResolver map[string][]net.IPAddr

func (r staticProxyResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	return append([]net.IPAddr(nil), r[host]...), nil
}

func TestProxyEnvironment(t *testing.T) {
	cfg := RunConfig{ProxyURL: "http://proxy.example:3128"}
	want := []string{
		"HTTP_PROXY=http://proxy.example:3128",
		"HTTPS_PROXY=http://proxy.example:3128",
		"ALL_PROXY=http://proxy.example:3128",
		"http_proxy=http://proxy.example:3128",
		"https_proxy=http://proxy.example:3128",
		"all_proxy=http://proxy.example:3128",
		"NO_PROXY=" + DefaultNoProxy,
		"no_proxy=" + DefaultNoProxy,
	}
	if got := cfg.ProxyEnvironment(); !reflect.DeepEqual(got, want) {
		t.Fatalf("proxy environment = %#v, want %#v", got, want)
	}

	cfg.NoProxy = "localhost,.corp.example"
	got := cfg.ProxyEnvironment()
	if got[len(got)-2] != "NO_PROXY=localhost,.corp.example" || got[len(got)-1] != "no_proxy=localhost,.corp.example" {
		t.Fatalf("custom no-proxy not applied: %v", got)
	}
}

func TestValidateProxyConfig(t *testing.T) {
	valid := []RunConfig{
		{Net: true, ProxyURL: "http://proxy.example:3128"},
		{Net: true, ProxyURL: "https://proxy.example"},
		{Net: true, ProxyURL: "socks5h://proxy.example:1080", ProxyEnforce: true},
	}
	for _, cfg := range valid {
		if err := ValidateProxyConfig(cfg); err != nil {
			t.Errorf("ValidateProxyConfig(%+v) = %v", cfg, err)
		}
	}

	invalid := []RunConfig{
		{Net: true, ProxyURL: "ftp://proxy.example"},
		{Net: true, ProxyURL: "http://user:password@proxy.example"},
		{Net: true, ProxyURL: "socks5://proxy.example"},
		{Net: false, ProxyURL: "http://proxy.example"},
		{Net: true, ProxyEnforce: true},
		{Net: true, NoProxy: "localhost"},
		{Net: true, ProxyURL: "http://proxy.example", ProxyEnforce: true, GVProxy: "gvproxy"},
	}
	for _, cfg := range invalid {
		if err := ValidateProxyConfig(cfg); err == nil {
			t.Errorf("ValidateProxyConfig(%+v) succeeded", cfg)
		}
	}
}

func TestProxyPolicyAllowsEndpointAndBlocksDirectWeb(t *testing.T) {
	base, err := netpol.Parse([]byte(`{"default":"allow","allowDomains":["api.example"]}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg := RunConfig{Net: true, ProxyURL: "http://proxy.example:3128", ProxyEnforce: true}
	policy, err := cfg.applyProxyPolicyWithResolver(base, staticProxyResolver{
		"proxy.example": {
			{IP: net.ParseIP("203.0.113.20")},
			{IP: net.ParseIP("203.0.113.10")},
			{IP: net.ParseIP("2001:db8::1")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Rules) < 4 {
		t.Fatalf("effective rules = %#v", policy.Rules)
	}
	if got := policy.Rules[0].CIDR.String(); got != "203.0.113.10/32" {
		t.Fatalf("first endpoint rule = %s, want deterministic ascending address", got)
	}
	for _, address := range [][4]byte{{203, 0, 113, 10}, {203, 0, 113, 20}} {
		if !policy.Allows(address, 6, 3128) {
			t.Errorf("proxy endpoint %v:3128 blocked", address)
		}
		if policy.Allows(address, 6, 443) {
			t.Errorf("proxy endpoint %v received an overly broad exception", address)
		}
	}
	if policy.Allows([4]byte{8, 8, 8, 8}, 6, 80) || policy.Allows([4]byte{8, 8, 8, 8}, 6, 443) {
		t.Fatal("direct TCP web egress remains allowed")
	}
	if policy.Allows([4]byte{8, 8, 8, 8}, 17, 443) {
		t.Fatal("direct QUIC egress remains allowed")
	}
	if !policy.Allows([4]byte{8, 8, 8, 8}, 6, 22) {
		t.Fatal("proxy enforcement unexpectedly blocked non-web traffic")
	}
	if !strings.Contains(strings.Join(policy.ResolveDomains, ","), "proxy.example") {
		t.Fatalf("proxy hostname missing from DNS-only list: %v", policy.ResolveDomains)
	}
	if strings.Contains(strings.Join(policy.AllowDomains, ","), "proxy.example") {
		t.Fatalf("proxy hostname received a broad dynamic allow: %v", policy.AllowDomains)
	}
}

func TestProxyPolicyRejectsLocalEndpointsUnlessAllowed(t *testing.T) {
	local := net.ParseIP("169.254.169.254")
	cfg := RunConfig{Net: true, ProxyURL: "http://proxy.example:80", ProxyEnforce: true}

	if _, err := cfg.applyProxyPolicyWithResolver(netpol.DefaultPolicy(), staticProxyResolver{
		"proxy.example": {{IP: local}},
	}); err == nil || !strings.Contains(err.Error(), "no permitted IPv4 address") {
		t.Fatalf("local-only proxy resolution returned error %v", err)
	}

	policy, err := cfg.applyProxyPolicyWithResolver(netpol.DefaultPolicy(), staticProxyResolver{
		"proxy.example": {{IP: local}, {IP: net.ParseIP("203.0.113.10")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if policy.Allows([4]byte{169, 254, 169, 254}, 6, 80) {
		t.Fatal("proxy policy allowed a DNS-resolved metadata endpoint")
	}
	if !policy.Allows([4]byte{203, 0, 113, 10}, 6, 80) {
		t.Fatal("proxy policy discarded a public endpoint")
	}

	allowLocal := netpol.DefaultPolicy()
	allowLocal.AllowLocal = true
	policy, err = cfg.applyProxyPolicyWithResolver(allowLocal, staticProxyResolver{
		"proxy.example": {{IP: local}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !policy.Allows([4]byte{169, 254, 169, 254}, 6, 80) {
		t.Fatal("proxy policy blocked a local endpoint when local access is enabled")
	}
}

func TestProxyPolicyRejectsLocalLiteral(t *testing.T) {
	cfg := RunConfig{Net: true, ProxyURL: "http://169.254.169.254:80"}
	if _, err := cfg.applyProxyPolicyWithResolver(netpol.DefaultPolicy(), nil); err == nil ||
		!strings.Contains(err.Error(), "no permitted IPv4 address") {
		t.Fatalf("local literal proxy returned error %v", err)
	}
}
