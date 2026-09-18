package sandbox

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/control"
)

// applyOrganizationPolicy reconciles one verified snapshot across every
// long-lived host enforcement point. Requests through credentials, MCP, and
// shares fail closed while network, share access, persistence, and expiry are
// moved to one generation.
func (d *daemonSupervisor) applyOrganizationPolicy(snapshot *policy.Config) error {
	d.policyUpdateMu.Lock()
	defer d.policyUpdateMu.Unlock()

	cfg := d.host.config().Snapshot()
	if sameLiveOrganizationPolicy(cfg.OrgPolicy, snapshot) {
		return nil
	}
	if snapshot != nil && cfg.OAuthCustodyEnabled() {
		return fmt.Errorf("organization policy v1 does not support OAuth custody")
	}
	engine, err := d.newOrganizationPolicyEngine(snapshot)
	if err != nil {
		return err
	}
	if snapshot != nil && cfg.GVProxy != "" {
		return fmt.Errorf("organization policy requires the embedded netstack")
	}

	oldEngine := d.governance.Snapshot()

	// The controller barrier covers host-side credentials and MCP. The share
	// barrier drains FUSE operations and covers existing handles separately.
	d.governance.SetBlocked(true)
	d.control.mcp.closeSessions()
	if shares := d.host.shareBorrow(); shares != nil {
		shares.SetPolicyBlocked(true)
	}
	releaseBarriers := true
	defer func() {
		if !releaseBarriers {
			return
		}
		if shares := d.host.shareBorrow(); shares != nil {
			shares.SetPolicyBlocked(false)
		}
		d.governance.SetBlocked(false)
	}()

	if d.host.networkTx == nil {
		d.host.networkTx = control.NewNetworkTransactionCoordinator()
	}
	return d.host.networkTx.Run(func() error {
		// Read both the persisted settings and effective network policy inside
		// the network transaction. A concurrent local net-policy or port update
		// therefore lands wholly before or after this organization generation.
		cfg = d.host.config().Snapshot()
		if d.control.broker == nil || d.control.broker.netPolicy == nil {
			return fmt.Errorf("live organization policy requires the daemon network policy controller")
		}
		if cfg.Net && (d.host.network == nil || d.host.network.Backend == nil) {
			return fmt.Errorf("live organization policy requires a running embedded netstack")
		}
		oldNetwork, err := d.control.broker.netPolicy.CurrentPolicy()
		if err != nil {
			return fmt.Errorf("snapshot current network policy: %w", err)
		}
		base, err := netpol.WithoutGuard(oldNetwork)
		if err != nil {
			return fmt.Errorf("prepare local network policy: %w", err)
		}
		nextNetwork, err := engine.ApplyNetwork(base)
		if err != nil {
			return fmt.Errorf("apply organization network policy: %w", err)
		}
		if err := control.ValidatePolicyAgainstSavedUDPPorts(nextNetwork, cfg.Ports); err != nil {
			return err
		}
		rollback := func(cause error, restoreShares bool) error {
			var rollbackErr error
			if shares := d.host.shareBorrow(); restoreShares && shares != nil {
				if err := shares.ReconcileOrganizationPolicy(oldEngine); err != nil {
					rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore previous share policy: %w", err))
				}
			}
			if err := d.control.broker.netPolicy.ReplaceEffectivePolicy(oldNetwork); err != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore previous live network policy: %w", err))
			}
			if rollbackErr != nil {
				releaseBarriers = false
				d.stopAfterPolicyReconciliationFailure()
				return errors.Join(cause, rollbackErr, errors.New("sandbox is stopping because organization-policy state is inconsistent"))
			}
			return cause
		}
		barrier, err := d.control.broker.netPolicy.FailClosedPolicy()
		if err != nil {
			return fmt.Errorf("prepare fail-closed network barrier: %w", err)
		}
		if err := d.control.broker.netPolicy.ReplaceEffectivePolicy(barrier); err != nil {
			return fmt.Errorf("enter fail-closed network barrier: %w", err)
		}
		if err := d.control.broker.netPolicy.ReplaceEffectivePolicy(nextNetwork); err != nil {
			return rollback(fmt.Errorf("apply live organization network policy: %w", err), false)
		}
		if shares := d.host.shareBorrow(); shares != nil {
			if err := shares.ReconcileOrganizationPolicy(engine); err != nil {
				// Manifest rollback is internal to ShareManager. Stop anyway if
				// its own fail-closed path left the hub unavailable.
				result := rollback(fmt.Errorf("apply live organization share policy: %w", err), false)
				if shares.Failed() {
					releaseBarriers = false
					d.stopAfterPolicyReconciliationFailure()
					result = errors.Join(result, errors.New("sandbox is stopping because organization-policy state is inconsistent"))
				}
				return result
			}
		}

		persistErr := d.host.config().SetOrganizationPolicy(snapshot)
		if persistErr != nil && !atomicfile.Committed(persistErr) {
			return rollback(persistErr, true)
		}

		d.governance.Store(engine)
		select {
		case d.policyChanged <- struct{}{}:
		default:
		}
		if persistErr != nil && d.host.audit != nil {
			d.host.audit.logf(d.dir, "policy: snapshot applied but configuration durability is uncertain: %v", persistErr)
		}
		return nil
	})
}

func (d *daemonSupervisor) stopAfterPolicyReconciliationFailure() {
	if d.control.shutdown == nil {
		return
	}
	select {
	case d.control.shutdown <- struct{}{}:
	default:
	}
}

func sameLiveOrganizationPolicy(left, right *policy.Config) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Profile == right.Profile && left.PublicKey == right.PublicKey && bytes.Equal(left.Bundle, right.Bundle)
}
