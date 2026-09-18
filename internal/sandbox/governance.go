package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/ejpir/gantry/internal/policy"
)

func (r *runResolver) resolveOrganizationPolicy() error {
	var snapshot *policy.Config
	if r.options.OrganizationSnapshot != nil {
		if r.options.OrgPolicy != "" || r.options.OrgPolicyKey != "" || r.options.PolicyProfile != "" {
			return fmt.Errorf("organization snapshot and policy file flags are mutually exclusive")
		}
		snapshot = policy.CloneConfig(r.options.OrganizationSnapshot)
		if _, err := policy.New(snapshot, nil); err != nil {
			return err
		}
	} else {
		var err error
		snapshot, err = policy.ReadConfig(r.options.OrgPolicy, r.options.OrgPolicyKey, r.options.PolicyProfile)
		if err != nil {
			return err
		}
	}
	if snapshot != nil && r.options.OAuthCustody {
		return fmt.Errorf("organization policy v1 does not support OAuth custody; disable -oauth-custody (host OAuth refresh/delivery is not yet governed)")
	}
	r.cfg.OrgPolicy = snapshot
	return nil
}

func (d *daemonSupervisor) loadOrganizationPolicy() error {
	if d.cfg.OrgPolicy != nil && d.cfg.OAuthCustodyEnabled() {
		return fmt.Errorf("organization policy v1 does not support OAuth custody")
	}
	engine, err := d.newOrganizationPolicyEngine(d.cfg.OrgPolicy)
	if err != nil {
		return err
	}
	d.governance = policy.NewController(engine)
	d.policyChanged = make(chan struct{}, 1)
	return nil
}

func (d *daemonSupervisor) newOrganizationPolicyEngine(snapshot *policy.Config) (*policy.Engine, error) {
	// The daemon-wide writer is available before the control broker and is
	// shared with it later, so early mount decisions persist and concurrent
	// policy/broker events cannot race audit.log rotation.
	engine, err := policy.New(snapshot, func(decision policy.Decision) {
		if d.host.Audit() != nil {
			raw, _ := json.Marshal(decision)
			d.host.Audit().logf(d.dir, "policy: %s", raw)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("organization policy: %w", err)
	}
	return engine, nil
}

func (d *daemonSupervisor) credentialAllowed(host string) bool {
	if d.control.Broker().domainAllowed != nil && !d.control.Broker().domainAllowed(host) {
		return false
	}
	return d.governance.Authorize(context.Background(), policy.CredentialUse, policy.Resource{Host: host}) == nil
}

// authorizeMCPDial runs on the exact IP selected by the supervisor's pinned
// transport. A host-side MCP upstream must not bypass the organization egress
// guard merely because its socket is outside the guest netstack.
func (d *daemonSupervisor) authorizeMCPDial(ctx context.Context, host string, ip net.IP, port string) error {
	if err := d.governance.Authorize(ctx, policy.NetworkResolve, policy.Resource{Host: host}); err != nil {
		return err
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return fmt.Errorf("invalid MCP upstream port")
	}
	return d.governance.Authorize(ctx, policy.NetworkConnect, policy.Resource{IP: ip.String(), Protocol: "tcp", Port: uint16(n)})
}
