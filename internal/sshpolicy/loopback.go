// Package sshpolicy contains SSH forwarding policy shared by the host gateway
// and the in-guest relay.
package sshpolicy

import (
	"net"
	"strings"
)

// ExactLoopbackTarget permits only the singular IPv4 and IPv6 loopback
// addresses. Other 127/8 addresses, IPv4-mapped IPv6, hostnames, and port zero
// are intentionally refused.
func ExactLoopbackTarget(host string, port uint64) bool {
	if port == 0 || port > 65535 {
		return false
	}
	ip := net.ParseIP(host)
	if strings.Contains(host, ":") {
		return ip != nil && ip.Equal(net.IPv6loopback)
	}
	return ip != nil && ip.Equal(net.IPv4(127, 0, 0, 1))
}
