package netpol

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// GuardSpec is an immutable organization restriction, intersected with the
// ordinary policy. DNS permissions permit resolution only, never IP access.
// The supervisor materializes this bounded plan from a verified OPA snapshot;
// workers need neither Rego nor access to policy files or signing keys.
type GuardSpec struct {
	Organization string      `json:"organization"`
	Revision     string      `json:"revision"`
	ExpiresAt    time.Time   `json:"expires_at"`
	Rules        []GuardRule `json:"rules"`
	DNS          []string    `json:"dns"`
}

type GuardRule struct {
	ID       string   `json:"id"`
	Effect   string   `json:"effect"`
	CIDR     string   `json:"cidr"`
	Protocol string   `json:"protocol"`
	Ports    []uint16 `json:"ports"`
}

type networkGuard struct {
	spec  GuardSpec
	rules []Rule
}

// ValidateGuard rejects features the native enforcement plane cannot express.
// Expiry is checked at use time, allowing expired snapshots to round-trip
// through worker shutdown and inspection without becoming unrestricted.
func ValidateGuard(spec GuardSpec) error {
	if spec.Organization == "" || len(spec.Organization) > 128 || spec.Revision == "" || len(spec.Revision) > 128 || spec.ExpiresAt.IsZero() {
		return fmt.Errorf("organization network guard requires bounded identity, revision and expiry")
	}
	if len(spec.Rules) > 256 || len(spec.DNS) > 256 {
		return fmt.Errorf("organization network guard exceeds rule limit")
	}
	seen := map[string]bool{}
	for _, rule := range spec.Rules {
		if rule.ID == "" || len(rule.ID) > 128 || seen[rule.ID] {
			return fmt.Errorf("invalid or duplicate organization network rule ID")
		}
		seen[rule.ID] = true
		if rule.Effect != "allow" && rule.Effect != "deny" {
			return fmt.Errorf("network rule %s: effect must be allow or deny", rule.ID)
		}
		prefix, err := netip.ParsePrefix(rule.CIDR)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return fmt.Errorf("network rule %s: CIDR must be a canonical IPv4 prefix", rule.ID)
		}
		switch rule.Protocol {
		case "tcp", "udp":
		case "any", "icmp":
			if len(rule.Ports) != 0 {
				return fmt.Errorf("network rule %s: ports require tcp or udp", rule.ID)
			}
		default:
			return fmt.Errorf("network rule %s: unsupported protocol", rule.ID)
		}
		if len(rule.Ports) > 64 {
			return fmt.Errorf("network rule %s: too many ports", rule.ID)
		}
		for _, port := range rule.Ports {
			if port == 0 {
				return fmt.Errorf("network rule %s: port zero is not supported", rule.ID)
			}
		}
	}
	for _, domain := range spec.DNS {
		if !ValidGuardDomain(domain) {
			return fmt.Errorf("invalid organization DNS pattern %q", domain)
		}
	}
	return nil
}

// ValidGuardDomain accepts exact ASCII names, *.suffix (including its apex),
// and *. The same small grammar is used by the embedded Rego evaluator.
func ValidGuardDomain(domain string) bool {
	if domain == "*" {
		return true
	}
	name := strings.TrimPrefix(domain, "*.")
	if name == "" || len(name) > 253 || name != strings.ToLower(name) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func parseGuard(spec GuardSpec) (*networkGuard, error) {
	if err := ValidateGuard(spec); err != nil {
		return nil, err
	}
	g := &networkGuard{spec: spec}
	g.spec.Rules = append([]GuardRule(nil), spec.Rules...)
	g.spec.DNS = append([]string(nil), spec.DNS...)
	for i, rule := range spec.Rules {
		g.spec.Rules[i].Ports = append([]uint16(nil), rule.Ports...)
		r := Rule{Deny: rule.Effect == "deny"}
		_, r.CIDR, _ = net.ParseCIDR(rule.CIDR)
		switch rule.Protocol {
		case "tcp":
			r.Proto = protoTCP
		case "udp":
			r.Proto = protoUDP
		case "icmp":
			r.Proto = protoICMP
		}
		for _, port := range rule.Ports {
			r.Ports = append(r.Ports, PortRange{port, port})
		}
		g.rules = append(g.rules, r)
	}
	return g, nil
}

func (g *networkGuard) valid() bool {
	return g == nil || time.Now().Before(g.spec.ExpiresAt)
}

func (g *networkGuard) allows(dst [4]byte, proto uint8, port uint16) bool {
	if g == nil {
		return true
	}
	if !g.valid() {
		return false
	}
	allowed := false
	for _, rule := range g.rules {
		if !rule.CIDR.Contains(net.IP(dst[:])) || rule.Proto != 0 && rule.Proto != proto {
			continue
		}
		matchesPort := len(rule.Ports) == 0
		for _, p := range rule.Ports {
			matchesPort = matchesPort || p.Lo == port
		}
		if !matchesPort {
			continue
		}
		if rule.Deny {
			return false
		}
		allowed = true
	}
	return allowed
}

func (g *networkGuard) domainAllowed(name string) bool {
	if g == nil {
		return true
	}
	if !g.valid() {
		return false
	}
	for _, domain := range g.spec.DNS {
		if domain == "*" {
			return true
		}
	}
	return domainMatches(g.spec.DNS, name)
}

// WithGuard attaches a detached guard to a detached local policy. Ordinary
// local-policy replacements inherit the running guard; the daemon's live
// organization transaction may exactly replace it.
func WithGuard(policy *Policy, spec GuardSpec) (*Policy, error) {
	guard, err := parseGuard(spec)
	if err != nil {
		return nil, err
	}
	clone, err := clonePolicy(policy)
	if err != nil {
		return nil, err
	}
	clone.guard = guard
	return clone, nil
}

// InheritGuard preserves the current immutable organization restriction when
// preparing a live local-policy update, including its persisted/rollback view.
func InheritGuard(next, current *Policy) {
	if next != nil && current != nil && current.current().guard != nil {
		next.guard = current.current().guard
	}
}

// WithoutGuard clones the local network policy while removing its
// organization overlay. It is used when a running daemon prepares a new
// signed organization generation without rereading the original policy file.
func WithoutGuard(current *Policy) (*Policy, error) {
	raw, err := Marshal(current)
	if err != nil {
		return nil, err
	}
	cloned, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	cloned.guard = nil
	return cloned, nil
}
