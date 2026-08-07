package sandbox

import (
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
