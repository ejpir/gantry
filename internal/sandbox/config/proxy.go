package config

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
)

const DefaultNoProxy = "localhost,127.0.0.1,::1"

type ForwardProxy struct {
	URL      string
	Hostname string
	Port     uint16
}

func ParseForwardProxy(raw string) (ForwardProxy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ForwardProxy{}, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ForwardProxy{}, fmt.Errorf("invalid proxy URL: %w", err)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	switch parsed.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return ForwardProxy{}, fmt.Errorf("proxy URL scheme must be http, https, socks5, or socks5h, got %q", parsed.Scheme)
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return ForwardProxy{}, fmt.Errorf("proxy URL must include a host")
	}
	if parsed.User != nil {
		return ForwardProxy{}, fmt.Errorf("proxy URL credentials cannot be persisted; inject authenticated proxy variables with -secret instead")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return ForwardProxy{}, fmt.Errorf("proxy URL must not include a path, query, or fragment")
	}
	if ip := net.ParseIP(parsed.Hostname()); ip != nil && ip.To4() == nil {
		return ForwardProxy{}, fmt.Errorf("proxy URL uses IPv6, but sandbox networking is IPv4-only")
	}

	port := parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return ForwardProxy{}, fmt.Errorf("%s proxy URL must include a port", parsed.Scheme)
		}
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return ForwardProxy{}, fmt.Errorf("proxy URL has invalid port %q", port)
	}

	return ForwardProxy{
		URL:      parsed.String(),
		Hostname: strings.ToLower(parsed.Hostname()),
		Port:     uint16(portNumber),
	}, nil
}

func validateNoProxy(value string) error {
	if strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("no-proxy list must not contain NUL or newlines")
	}
	return nil
}

func (c RunConfig) ProxyEnvironment() []string {
	proxy, err := ParseForwardProxy(c.ProxyURL)
	if err != nil || proxy.URL == "" {
		return nil
	}
	noProxy := c.NoProxy
	if noProxy == "" {
		noProxy = DefaultNoProxy
	}
	return []string{
		"HTTP_PROXY=" + proxy.URL,
		"HTTPS_PROXY=" + proxy.URL,
		"ALL_PROXY=" + proxy.URL,
		"http_proxy=" + proxy.URL,
		"https_proxy=" + proxy.URL,
		"all_proxy=" + proxy.URL,
		"NO_PROXY=" + noProxy,
		"no_proxy=" + noProxy,
	}
}

func ValidateProxyConfig(c RunConfig) error {
	proxy, err := ParseForwardProxy(c.ProxyURL)
	if err != nil {
		return err
	}
	if err := validateNoProxy(c.NoProxy); err != nil {
		return err
	}
	if proxy.URL == "" {
		if c.ProxyEnforce {
			return fmt.Errorf("proxy enforcement requires -proxy")
		}
		if c.NoProxy != "" {
			return fmt.Errorf("-no-proxy requires -proxy")
		}
		return nil
	}
	if !c.Net {
		return fmt.Errorf("proxy routing requires networking (remove -net=false)")
	}
	if c.ProxyEnforce && c.GVProxy != "" {
		return fmt.Errorf("-proxy-enforce requires the embedded netstack (remove -gvproxy)")
	}
	return nil
}

type proxyIPResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

func (c RunConfig) ApplyProxyPolicy(policy *netpol.Policy) (*netpol.Policy, error) {
	return c.applyProxyPolicyWithResolver(policy, net.DefaultResolver)
}

func (c RunConfig) applyProxyPolicyWithResolver(policy *netpol.Policy, resolver proxyIPResolver) (*netpol.Policy, error) {
	proxy, err := ParseForwardProxy(c.ProxyURL)
	if err != nil {
		return nil, err
	}
	if proxy.URL == "" {
		return policy, nil
	}
	if policy == nil {
		policy = netpol.DefaultPolicy()
	}

	var addresses []net.IP
	if literal := net.ParseIP(proxy.Hostname); literal != nil {
		addresses = []net.IP{literal}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resolved, err := resolver.LookupIPAddr(ctx, proxy.Hostname)
		if err != nil {
			return nil, fmt.Errorf("resolve proxy host %s: %w", proxy.Hostname, err)
		}
		for _, address := range resolved {
			if v4 := address.IP.To4(); v4 != nil {
				addresses = append(addresses, append(net.IP(nil), v4...))
			}
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("proxy host %s has no IPv4 address", proxy.Hostname)
	}

	// A policy with a DNS allowlist must permit the proxy hostname to be
	// resolved inside the guest as well. The narrow IP/port rules below are
	// still what let the connection pass explicit proxy-only web denies.
	if net.ParseIP(proxy.Hostname) == nil && (len(policy.AllowDomains) != 0 || len(policy.ResolveDomains) != 0) {
		policy, err = netpol.WithResolveDomain(policy, proxy.Hostname)
		if err != nil {
			return nil, err
		}
	}
	if c.ProxyEnforce {
		// Apply generic denies first because WithRule prepends. Endpoint allows
		// are added afterwards and therefore remain the highest-priority rules.
		policy, err = netpol.WithRule(policy, netpol.RuleSpec{
			Action: "deny", Protocol: "udp", Ports: "443",
		})
		if err != nil {
			return nil, err
		}
		policy, err = netpol.WithRule(policy, netpol.RuleSpec{
			Action: "deny", Protocol: "tcp", Ports: "80,443",
		})
		if err != nil {
			return nil, err
		}
	}

	unique := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		if v4 := address.To4(); v4 != nil {
			// These endpoint rules take priority over the local-network wall.
			// Never synthesize that exception unless local access was explicitly
			// enabled: a proxy hostname may return a poisoned or malicious DNS
			// answer for metadata, the host alias, or another LAN service.
			if !policy.AllowLocal && netpol.IsLocalIP(v4) {
				continue
			}
			unique[v4.String()] = struct{}{}
		}
	}
	if len(unique) == 0 {
		return nil, fmt.Errorf("proxy host %s has no permitted IPv4 address", proxy.Hostname)
	}
	ordered := make([]string, 0, len(unique))
	for address := range unique {
		ordered = append(ordered, address)
	}
	sort.Strings(ordered)
	// Iterate backwards because each rule is prepended; the final evaluation
	// order remains stable and ascending for reproducible diagnostics.
	for index := len(ordered) - 1; index >= 0; index-- {
		policy, err = netpol.WithRule(policy, netpol.RuleSpec{
			Action: "allow", CIDR: ordered[index] + "/32", Protocol: "tcp",
			Ports: strconv.Itoa(int(proxy.Port)),
		})
		if err != nil {
			return nil, err
		}
	}
	return policy, nil
}
