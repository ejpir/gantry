package control

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/vnet"
)

// NetworkBackend is the control surface the PortManager and
// NetworkPolicyManager mutate the live network through (Phase 0 seam of
// docs/vmm-network-isolation.md). Its enforcement implementations are:
//
//   - localBackend: the monolithic in-process netstack + policy, used
//     when process isolation is off or unavailable;
//   - the split-mode network worker client (network_worker.go), which
//     performs the same operations over workerproto RPC against the
//     re-executed `gantry _net-worker` process and is decorated by
//     policyMirrorBackend for supervisor-side policy decisions.
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

// NetworkTransactionCoordinator serializes the complete live-change,
// persistence, and rollback transactions performed by the policy and port
// managers that share one backend. Backend locks alone are too narrow: a
// policy write failure must be able to restore the old policy before a UDP
// publish observes the temporary policy (and vice versa).
type NetworkTransactionCoordinator struct {
	mu sync.Mutex
}

func NewNetworkTransactionCoordinator() *NetworkTransactionCoordinator {
	return &NetworkTransactionCoordinator{}
}

type localNetworkStack interface {
	Publish(proto, local, remote string) error
	Unpublish(proto, local string) error
	Forwards() ([]vnet.Forward, error)
}

// localBackend wraps the embedded netstack and stable policy holder the
// monolithic daemon has always used.
type localBackend struct {
	stack localNetworkStack
	live  *netpol.Policy
	mu    sync.Mutex
}

// NewLocalBackend binds the interface to the in-process stack. live may
// be nil (no policy configured); SetPolicy then still validates by
// keeping the swap on the stable holder — Replace rejects a nil target,
// so a nil live means policy mutation is unavailable.
func NewLocalBackend(stack *vnet.Stack, live *netpol.Policy) NetworkBackend {
	var localStack localNetworkStack
	if stack != nil {
		localStack = stack
	}
	return &localBackend{stack: localStack, live: live}
}

func (b *localBackend) Publish(proto, local, remote string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if proto == "udp" {
		if err := netpol.ValidateUDPPortPublishing(b.live); err != nil {
			return err
		}
	}
	if b.stack == nil {
		return fmt.Errorf("network stack is nil")
	}
	return b.stack.Publish(proto, local, remote)
}

func (b *localBackend) Unpublish(proto, local string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stack == nil {
		return fmt.Errorf("network stack is nil")
	}
	return b.stack.Unpublish(proto, local)
}

func (b *localBackend) Forwards() ([]vnet.Forward, error) {
	if b.stack == nil {
		return nil, fmt.Errorf("network stack is nil")
	}
	return b.stack.Forwards()
}

func (b *localBackend) SetPolicy(policy *netpol.Policy) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if policy == nil {
		return b.live.Replace(nil)
	}
	if b.stack == nil {
		return fmt.Errorf("network stack is nil")
	}
	forwards, err := b.stack.Forwards()
	if err != nil {
		return fmt.Errorf("list active port forwards: %w", err)
	}
	if err := validatePolicyAgainstUDPForwards(policy, forwards); err != nil {
		return err
	}
	return b.live.Replace(policy)
}

func validatePolicyAgainstUDPForwards(policy *netpol.Policy, forwards []vnet.Forward) error {
	for _, forward := range forwards {
		if forward.Protocol != "udp" {
			continue
		}
		if err := netpol.ValidateUDPPortPublishing(policy); err != nil {
			return fmt.Errorf("active UDP port forward %s -> %s: %w", forward.Local, forward.Remote, err)
		}
		return nil
	}
	return nil
}

// policyMirrorBackend keeps a supervisor-owned stable Policy holder in sync
// with an out-of-process enforcement backend. Host-side decisions such as the
// bound-credential egress gate follow that holder through Policy.Replace.
type policyMirrorBackend struct {
	NetworkBackend
	live *netpol.Policy
	mu   sync.Mutex
}

// NewPolicyMirrorBackend wraps a split backend so a successful live update is
// reflected in the supervisor only after the enforcement point accepts it.
func NewPolicyMirrorBackend(backend NetworkBackend, live *netpol.Policy) (NetworkBackend, error) {
	if backend == nil || live == nil {
		return nil, fmt.Errorf("network policy mirror backend is nil")
	}
	return &policyMirrorBackend{NetworkBackend: backend, live: live}, nil
}

func (b *policyMirrorBackend) SetPolicy(policy *netpol.Policy) error {
	if policy == nil {
		return fmt.Errorf("network policy replacement is nil")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.NetworkBackend.SetPolicy(policy); err != nil {
		return err
	}
	// live and policy were checked above, so Replace cannot fail after the
	// split backend has committed the policy.
	return b.live.Replace(policy)
}

// VMMPolicyPusher is the slice of the _vmm-worker the policy fan-out
// needs; an interface keeps this file platform-neutral (the concrete
// worker type only exists on unix).
type VMMPolicyPusher interface {
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
	vw      VMMPolicyPusher
	current *netpol.Policy // immutable snapshot of the last common policy
	mu      sync.Mutex
}

func NewVMMPolicyBackend(backend NetworkBackend, vw VMMPolicyPusher, current *netpol.Policy) (*vmmPolicyBackend, error) {
	if backend == nil || vw == nil {
		return nil, fmt.Errorf("network policy fan-out backend is nil")
	}
	snapshot, err := ClonePolicy(current)
	if err != nil {
		return nil, fmt.Errorf("snapshot current network policy: %w", err)
	}
	return &vmmPolicyBackend{NetworkBackend: backend, vw: vw, current: snapshot}, nil
}

func (b *vmmPolicyBackend) SetPolicy(policy *netpol.Policy) error {
	next, err := ClonePolicy(policy)
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

// ClonePolicy snapshots the currently effective immutable policy.
// This is deliberately a marshal/parse round trip: a Policy may be the stable
// holder attached to a device, whose active pointer changes on Replace. Keeping
// that holder as "previous" would make rollback silently point at the new state.
func ClonePolicy(policy *netpol.Policy) (*netpol.Policy, error) {
	raw, err := netpol.Marshal(policy)
	if err != nil {
		return nil, err
	}
	return netpol.Parse(raw)
}
