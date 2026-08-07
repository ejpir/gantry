package sandbox

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/vnet"
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
	store *ConfigStore
	live  *netpol.Policy
	stack *vnet.Stack
	mu    sync.Mutex
}

func NewNetworkPolicyManager(store *ConfigStore, live *netpol.Policy, stack *vnet.Stack) *NetworkPolicyManager {
	return &NetworkPolicyManager{store: store, live: live, stack: stack}
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
	if m.stack == nil || m.live == nil {
		return NetworkPolicyEntry{}, fmt.Errorf("live network policy updates require a running embedded netstack")
	}
	path, policy, err := resolveNetworkPolicy(path, allowLocal)
	if err != nil {
		return NetworkPolicyEntry{}, err
	}
	// Apply live FIRST and persist only on success: if Replace ever gains
	// a real failure mode, the on-disk config must not claim a policy the
	// running sandbox never enforced.
	if err := m.live.Replace(policy); err != nil {
		return NetworkPolicyEntry{}, err
	}
	if err := m.store.SetNetworkPolicy(path, allowLocal); err != nil {
		return NetworkPolicyEntry{}, err
	}
	return makeNetworkPolicyEntry(path, allowLocal, policy, "active"), nil
}

func (m *NetworkPolicyManager) Get() (NetworkPolicyEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := m.store.Snapshot()
	if m.stack != nil && m.live != nil {
		// The source file may be moved after boot. The running policy is already
		// parsed and remains authoritative, so showing it must not depend on the
		// file still being present.
		return makeNetworkPolicyEntry(cfg.NetPol, cfg.AllowLN, m.live, "active"), nil
	}
	_, policy, err := resolveNetworkPolicy(cfg.NetPol, cfg.AllowLN)
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

	path, policy, err := resolveNetworkPolicy(path, allowLocal)
	if err != nil {
		return NetworkPolicyEntry{}, err
	}
	store, err := LoadConfigStore(sandboxDir(name))
	if err != nil {
		return NetworkPolicyEntry{}, err
	}
	if err := store.SetNetworkPolicy(path, allowLocal); err != nil {
		return NetworkPolicyEntry{}, err
	}
	return makeNetworkPolicyEntry(path, allowLocal, policy, "saved"), nil
}
