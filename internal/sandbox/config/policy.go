package config

import (
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/policy"
)

// ApplyOrganizationPolicy is the stopped-sandbox inspection/preflight path.
// Running sandboxes use their already-verified immutable snapshot, never a
// fresh file read or a possibly different generation during a local update.
func (c RunConfig) ApplyOrganizationPolicy(local *netpol.Policy) (*netpol.Policy, error) {
	engine, err := policy.New(c.OrgPolicy, nil)
	if err != nil {
		return nil, err
	}
	return engine.ApplyNetwork(local)
}
