package sandbox

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/vnet"
)

// NetworkBackend is the control surface the PortManager and
// NetworkPolicyManager mutate the live network through (Phase 0 seam of
// docs/vmm-network-isolation.md). It has exactly two implementations:
//
//   - localBackend: the monolithic in-process netstack + policy, used
//     when process isolation is off or unavailable;
//   - the split-mode network worker client (network_worker.go), which
//     performs the same operations over workerproto RPC against the
//     re-executed `gantry _net-worker` process.
//
// The managers below never know which one they hold, so live policy
// replacement and port publishing keep identical transactional semantics
// in both topologies.
type NetworkBackend interface {
	// Publish opens a host listener forwarding into the guest.
	Publish(proto, local, remote string) error
	// Unpublish tears down the listener for proto+local.
	Unpublish(proto, local string) error
	// Forwards lists every active proxy, boot-configured and live.
	Forwards() ([]vnet.Forward, error)
	// SetPolicy atomically swaps the enforced egress policy. The
	// receiver validates the (already normalized) policy before it
	// takes effect; a failure leaves the previous policy enforced.
	SetPolicy(policy *netpol.Policy) error
}

// localBackend wraps the embedded netstack and stable policy holder the
// monolithic daemon has always used.
type localBackend struct {
	stack *vnet.Stack
	live  *netpol.Policy
}

// newLocalBackend binds the interface to the in-process stack. live may
// be nil (no policy configured); SetPolicy then still validates by
// keeping the swap on the stable holder — Replace rejects a nil target,
// so a nil live means policy mutation is unavailable.
func newLocalBackend(stack *vnet.Stack, live *netpol.Policy) NetworkBackend {
	return &localBackend{stack: stack, live: live}
}

func (b *localBackend) Publish(proto, local, remote string) error {
	return b.stack.Publish(proto, local, remote)
}

func (b *localBackend) Unpublish(proto, local string) error {
	return b.stack.Unpublish(proto, local)
}

func (b *localBackend) Forwards() ([]vnet.Forward, error) { return b.stack.Forwards() }

func (b *localBackend) SetPolicy(policy *netpol.Policy) error {
	return b.live.Replace(policy)
}

// vmmPolicyPusher is the slice of the _vmm-worker the policy fan-out
// needs; an interface keeps this file platform-neutral (the concrete
// worker type only exists on unix).
type vmmPolicyPusher interface {
	SetPolicy(*netpol.Policy) error
	Close() error
}

// vmmPolicyBackend fans live policy swaps out to a split _vmm-worker
// that enforces the local netstack's policy (degraded topology: the
// net-worker failed, the VMM split succeeded). The supervisor-side swap
// keeps display and rollback state consistent; the worker push is the
// actual enforcement. Rollback works because the manager re-invokes
// SetPolicy with the previous policy, which re-pushes it.
type vmmPolicyBackend struct {
	NetworkBackend
	vw      vmmPolicyPusher
	current *netpol.Policy // immutable snapshot of the last common policy
	mu      sync.Mutex
}

func newVMMPolicyBackend(backend NetworkBackend, vw vmmPolicyPusher, current *netpol.Policy) (*vmmPolicyBackend, error) {
	if backend == nil || vw == nil {
		return nil, fmt.Errorf("network policy fan-out backend is nil")
	}
	snapshot, err := cloneNetworkPolicy(current)
	if err != nil {
		return nil, fmt.Errorf("snapshot current network policy: %w", err)
	}
	return &vmmPolicyBackend{NetworkBackend: backend, vw: vw, current: snapshot}, nil
}

func (b *vmmPolicyBackend) SetPolicy(policy *netpol.Policy) error {
	next, err := cloneNetworkPolicy(policy)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	// The VMM is the enforcement point in this degraded topology. Push it
	// first so a worker failure cannot mutate the supervisor's display and
	// rollback holder. If the local mirror then fails, restore the VMM before
	// reporting failure; callers may rely on "error leaves previous policy".
	if err := b.vw.SetPolicy(next); err != nil {
		// The RPC may have applied in the worker and lost its response. With no
		// VMM-side status protocol, continuing would make the enforcement state
		// unknowable. Stop the worker so the sandbox fails closed.
		return errors.Join(err, errors.New("VMM policy update unconfirmed; VMM stopped"), b.vw.Close())
	}
	if err := b.NetworkBackend.SetPolicy(next); err != nil {
		rollbackErr := b.vw.SetPolicy(b.current)
		if rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback VMM policy: %w", rollbackErr),
				errors.New("VMM policy rollback unconfirmed; VMM stopped"), b.vw.Close())
		}
		return err
	}
	b.current = next
	return nil
}

// cloneNetworkPolicy snapshots the currently effective immutable policy.
// This is deliberately a marshal/parse round trip: a Policy may be the stable
// holder attached to a device, whose active pointer changes on Replace. Keeping
// that holder as "previous" would make rollback silently point at the new state.
func cloneNetworkPolicy(policy *netpol.Policy) (*netpol.Policy, error) {
	raw, err := netpol.Marshal(policy)
	if err != nil {
		return nil, err
	}
	return netpol.Parse(raw)
}
