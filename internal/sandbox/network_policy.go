package sandbox

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/netpol"
)

type NetworkPolicyEntry struct {
	Path        string               `json:"path,omitempty"`
	AllowLocal  bool                 `json:"allow_local"`
	Description string               `json:"description"`
	State       string               `json:"state"` // active | saved
	Rules       []netpol.RuleSummary `json:"rules,omitempty"`
}

func makeNetworkPolicyEntry(path string, allowLocal bool, policy *netpol.Policy, state string) NetworkPolicyEntry {
	return NetworkPolicyEntry{
		Path: path, AllowLocal: allowLocal, Description: policy.Describe(),
		State: state, Rules: policy.RuleSummaries(),
	}
}

type NetworkPolicyManager struct {
	store   *ConfigStore
	backend NetworkBackend
	// current is the last successfully applied policy: what Get reports
	// for a running sandbox and what a persistence failure rolls the live
	// state back to. In split mode it is the supervisor's copy of the
	// policy the network worker enforces.
	current *netpol.Policy
	mu      sync.Mutex
}

func NewNetworkPolicyManager(store *ConfigStore, backend NetworkBackend, current *netpol.Policy) *NetworkPolicyManager {
	// current must not alias the stable holder mutated by localBackend.Replace:
	// persistence rollback needs an immutable snapshot of the policy that was
	// active before the attempted update.
	if snapshot, err := cloneNetworkPolicy(current); err == nil {
		current = snapshot
	}
	return &NetworkPolicyManager{store: store, backend: backend, current: current}
}

func resolveNetworkPolicy(path string, allowLocal bool) (string, *netpol.Policy, error) {
	var policy *netpol.Policy
	if path == "" {
		policy = netpol.DefaultPolicy()
	} else {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return "", nil, err
		}
		resolved, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			return "", nil, err
		}
		policy, err = netpol.Load(resolved)
		if err != nil {
			return "", nil, err
		}
		path = resolved
	}
	if allowLocal {
		policy.AllowLocal = true
	}
	return path, policy, nil
}

func (m *NetworkPolicyManager) Set(path string, allowLocal bool) (NetworkPolicyEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backend == nil || m.current == nil {
		return NetworkPolicyEntry{}, fmt.Errorf("live network policy updates require a running embedded netstack")
	}
	path, policy, err := resolveNetworkPolicy(path, allowLocal)
	if err != nil {
		return NetworkPolicyEntry{}, err
	}
	policy, err = m.store.Snapshot().applyProxyPolicy(policy)
	if err != nil {
		return NetworkPolicyEntry{}, err
	}
	// Apply live FIRST and persist only on success, rolling the live
	// state back if persistence fails: the on-disk config must never
	// claim a policy the running sandbox does not enforce, and the
	// running sandbox must not enforce a policy the config rejects.
	if err := m.backend.SetPolicy(policy); err != nil {
		return NetworkPolicyEntry{}, err
	}
	if err := m.store.SetNetworkPolicy(path, allowLocal); err != nil {
		if atomicfile.Committed(err) {
			m.current = policy
			return makeNetworkPolicyEntry(path, allowLocal, policy, "active"),
				fmt.Errorf("network policy applied but configuration durability is uncertain: %w", err)
		}
		if rollbackErr := m.backend.SetPolicy(m.current); rollbackErr != nil {
			return NetworkPolicyEntry{}, errors.Join(err,
				fmt.Errorf("restore previous live network policy: %w", rollbackErr))
		}
		return NetworkPolicyEntry{}, err
	}
	m.current = policy
	return makeNetworkPolicyEntry(path, allowLocal, policy, "active"), nil
}

func (m *NetworkPolicyManager) Get() (NetworkPolicyEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := m.store.Snapshot()
	if m.backend != nil && m.current != nil {
		// The source file may be moved after boot. The running policy is already
		// parsed and remains authoritative, so showing it must not depend on the
		// file still being present.
		return makeNetworkPolicyEntry(cfg.NetPol, cfg.AllowLN, m.current, "active"), nil
	}
	_, policy, err := resolveNetworkPolicy(cfg.NetPol, cfg.AllowLN)
	if err != nil {
		return NetworkPolicyEntry{}, err
	}
	policy, err = cfg.applyProxyPolicy(policy)
	if err != nil {
		return NetworkPolicyEntry{}, err
	}
	return makeNetworkPolicyEntry(cfg.NetPol, cfg.AllowLN, policy, "saved"), nil
}

type brokerNetworkPolicyRequest struct {
	Path       string `json:"path,omitempty"`
	AllowLocal bool   `json:"allow_local"`
}

type brokerNetworkPolicyResponse struct {
	OK     bool                `json:"ok"`
	Error  string              `json:"error,omitempty"`
	Policy *NetworkPolicyEntry `json:"policy,omitempty"`
}

func setSandboxNetworkPolicy(name, path string, allowLocal bool) (NetworkPolicyEntry, error) {
	if err := ValidateSandboxName(name); err != nil {
		return NetworkPolicyEntry{}, err
	}
	if _, alive := sandboxPID(name); alive {
		// The daemon runs with cwd=/, so a relative path would resolve
		// against / there. Canonicalize HERE (same resolution the daemon
		// applies) so the path means the caller's file.
		if path != "" {
			absolute, err := filepath.Abs(path)
			if err != nil {
				return NetworkPolicyEntry{}, err
			}
			resolved, err := filepath.EvalSymlinks(absolute)
			if err != nil {
				return NetworkPolicyEntry{}, err
			}
			path = resolved
		}
		return networkPolicyRPC(name, "netpolicy.set", &brokerNetworkPolicyRequest{Path: path, AllowLocal: allowLocal})
	}

	store, err := LoadConfigStore(sandboxDir(name))
	if err != nil {
		return NetworkPolicyEntry{}, err
	}
	path, policy, err := resolveNetworkPolicy(path, allowLocal)
	if err != nil {
		return NetworkPolicyEntry{}, err
	}
	policy, err = store.Snapshot().applyProxyPolicy(policy)
	if err != nil {
		return NetworkPolicyEntry{}, err
	}
	if err := store.SetNetworkPolicy(path, allowLocal); err != nil {
		return NetworkPolicyEntry{}, err
	}
	return makeNetworkPolicyEntry(path, allowLocal, policy, "saved"), nil
}
