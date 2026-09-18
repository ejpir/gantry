package vmmworker

import (
	"net"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/sharefs"
)

// Runner is the split-VMM execution handle: the guest runs in a _vmm-worker
// process and every interaction crosses a channel. The platform stubs make
// TryStart always fail where unsupported.
type Runner interface {
	// Wait parks until the guest exits (the split-mode guestErr).
	Wait() error
	// Close flushes devices and stops the worker (idempotent).
	Close() error
	// RequestHotMemory starts post-readiness virtio-mem expansion (a no-op
	// when the machine uses an ordinary e820 memory map).
	RequestHotMemory() error
	// Done closes when the worker process is reaped; Err reports how.
	Done() <-chan struct{}
	Err() error
	// DialStream opens a host->guest stream to a guest listening port.
	DialStream(guestPort uint32) (net.Conn, error)
}

// ShareProvider is the borrowed share capability needed while constructing a
// split VMM. Its owner remains responsible for shutdown.
type ShareProvider interface {
	Hub() sharefs.BorrowedHub
}

// NetAttachment is the borrowed network capability handed to a split VMM
// worker. It exposes topology and policy observations, never the owning
// connection's Close method.
type NetAttachment interface {
	Available() bool
	IsSplit() bool
	NetworkPolicy() *netpol.Policy
	TrafficRecorder() *netpol.TrafficRecorder
}

type netAttachment struct {
	available bool
	split     bool
	policy    *netpol.Policy
	traffic   *netpol.TrafficRecorder
}

func BorrowNetworkAttachment(conn net.Conn, split bool, policy *netpol.Policy, traffic *netpol.TrafficRecorder) NetAttachment {
	return netAttachment{available: conn != nil, split: split, policy: policy, traffic: traffic}
}
func (n netAttachment) Available() bool                          { return n.available }
func (n netAttachment) IsSplit() bool                            { return n.split }
func (n netAttachment) NetworkPolicy() *netpol.Policy            { return n.policy }
func (n netAttachment) TrafficRecorder() *netpol.TrafficRecorder { return n.traffic }

// vmmWorkerSpawnHook, when set, rewrites the re-exec argv/env (tests only:
// os.Executable() is the test binary under `go test`).
var vmmWorkerSpawnHook func(argv *[]string, env *[]string)
