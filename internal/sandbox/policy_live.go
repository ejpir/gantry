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
func (d *daemonRuntime) applyOrganizationPolicy(snapshot *policy.Config) error {
	d.policyUpdateMu.Lock()
	defer d.policyUpdateMu.Unlock()

	cfg := d.store.Snapshot()
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
	if d.mcpWorker != nil {
		d.mcpWorker.CloseSessions()
	}
	if d.shares != nil {
		d.shares.SetPolicyBlocked(true)
	}
	releaseBarriers := true
	defer func() {
		if !releaseBarriers {
			return
		}
		if d.shares != nil {
			d.shares.SetPolicyBlocked(false)
		}
		d.governance.SetBlocked(false)
	}()

	if d.networkTransactions == nil {
		d.networkTransactions = control.NewNetworkTransactionCoordinator()
	}
	return d.networkTransactions.Run(func() error {
		// Read both the persisted settings and effective network policy inside
		// the network transaction. A concurrent local net-policy or port update
		// therefore lands wholly before or after this organization generation.
		cfg = d.store.Snapshot()
		if d.broker == nil || d.broker.netPolicy == nil {
			return fmt.Errorf("live organization policy requires the daemon network policy controller")
		}
		if cfg.Net && (d.network == nil || d.network.Backend == nil) {
			return fmt.Errorf("live organization policy requires a running embedded netstack")
		}
		oldNetwork, err := d.broker.netPolicy.CurrentPolicy()
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
			if restoreShares && d.shares != nil {
				if err := d.shares.ReconcileOrganizationPolicy(oldEngine); err != nil {
					rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore previous share policy: %w", err))
				}
			}
			if err := d.broker.netPolicy.ReplaceEffectivePolicy(oldNetwork); err != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore previous live network policy: %w", err))
			}
			if rollbackErr != nil {
				releaseBarriers = false
				d.stopAfterPolicyReconciliationFailure()
				return errors.Join(cause, rollbackErr, errors.New("sandbox is stopping because organization-policy state is inconsistent"))
			}
			return cause
		}
		barrier, err := d.broker.netPolicy.FailClosedPolicy()
		if err != nil {
			return fmt.Errorf("prepare fail-closed network barrier: %w", err)
		}
		if err := d.broker.netPolicy.ReplaceEffectivePolicy(barrier); err != nil {
			return fmt.Errorf("enter fail-closed network barrier: %w", err)
		}
		if err := d.broker.netPolicy.ReplaceEffectivePolicy(nextNetwork); err != nil {
			return rollback(fmt.Errorf("apply live organization network policy: %w", err), false)
		}
		if d.shares != nil {
			if err := d.shares.ReconcileOrganizationPolicy(engine); err != nil {
				// Manifest rollback is internal to ShareManager. Stop anyway if
				// its own fail-closed path left the hub unavailable.
				result := rollback(fmt.Errorf("apply live organization share policy: %w", err), false)
				if d.shares.Failed() {
					releaseBarriers = false
					d.stopAfterPolicyReconciliationFailure()
					result = errors.Join(result, errors.New("sandbox is stopping because organization-policy state is inconsistent"))
				}
				return result
			}
		}

		persistErr := d.store.SetOrganizationPolicy(snapshot)
		if persistErr != nil && !atomicfile.Committed(persistErr) {
			return rollback(persistErr, true)
		}

		d.governance.Store(engine)
		select {
		case d.policyChanged <- struct{}{}:
		default:
		}
		if persistErr != nil && d.audit != nil {
			d.audit.logf(d.dir, "policy: snapshot applied but configuration durability is uncertain: %v", persistErr)
		}
		return nil
	})
}

func (d *daemonRuntime) stopAfterPolicyReconciliationFailure() {
	if d.shutdown == nil {
		return
	}
	select {
	case d.shutdown <- struct{}{}:
	default:
	}
}

func sameLiveOrganizationPolicy(left, right *policy.Config) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Profile == right.Profile && left.PublicKey == right.PublicKey && bytes.Equal(left.Bundle, right.Bundle)
}
