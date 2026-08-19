package controlcmd

// The client half of `gantry net-policy`: a running sandbox is mutated through
// its daemon's control socket, a stopped one directly through its persisted
// configuration. The daemon-side manager lives in the control package.

import (
	"fmt"
	"path/filepath"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func SetNetworkPolicy(name, path string, allowLocal bool) (control.NetworkPolicyEntry, error) {
	if err := layout.ValidateName(name); err != nil {
		return control.NetworkPolicyEntry{}, err
	}
	liveSet := func() (control.NetworkPolicyEntry, error) {
		// The daemon runs with cwd=/, so a relative path would resolve
		// against / there. Canonicalize HERE (same resolution the daemon
		// applies) so the path means the caller's file.
		if path != "" {
			absolute, err := filepath.Abs(path)
			if err != nil {
				return control.NetworkPolicyEntry{}, err
			}
			resolved, err := filepath.EvalSymlinks(absolute)
			if err != nil {
				return control.NetworkPolicyEntry{}, err
			}
			path = resolved
		}
		return networkPolicyRPC(name, "netpolicy.set", &controlproto.NetworkPolicyRequest{Path: path, AllowLocal: allowLocal})
	}
	if _, alive := layout.PID(name); alive {
		return liveSet()
	}

	// A daemon may be mid-boot between our liveness check and the store
	// write: it reads sandbox.json while its launcher holds the launch lock,
	// and it would never observe a policy persisted in that window (the
	// running sandbox would keep enforcing the old — possibly more
	// permissive — egress policy while the user is told the new one saved).
	// Take the launch lock so the write is serialized against boot.
	lock, err := layout.HoldLaunchLock(name)
	if err != nil {
		if _, alive := layout.PID(name); alive {
			return liveSet()
		}
		return control.NetworkPolicyEntry{}, fmt.Errorf("sandbox %q is launching; retry the network policy update when it is up or fully stopped", name)
	}
	defer func() { _ = lock.Close() }()
	// A daemon that began booting before we took the lock holds it until
	// readiness, so this second check cannot race its config load.
	if _, alive := layout.PID(name); alive {
		return liveSet()
	}

	store, err := config.LoadConfigStore(layout.Dir(name))
	if err != nil {
		return control.NetworkPolicyEntry{}, err
	}
	path, policy, err := control.ResolveNetworkPolicy(path, allowLocal)
	if err != nil {
		return control.NetworkPolicyEntry{}, err
	}
	policy, err = store.Snapshot().ApplyProxyPolicy(policy)
	if err != nil {
		return control.NetworkPolicyEntry{}, err
	}
	if err := store.SetNetworkPolicy(path, allowLocal); err != nil {
		return control.NetworkPolicyEntry{}, err
	}
	return control.MakeNetworkPolicyEntry(path, allowLocal, policy, "saved"), nil
}
