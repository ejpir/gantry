package vmmworker

import (
	"net"

	"github.com/ejpir/gantry/internal/netpol"
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

// NetAttachment is the network capability handed to a split VMM worker: the
// supervisor end of the guest's data channel, plus the policy and recorder
// this worker is responsible for enforcing.
//
// Split reports that networking runs in its own worker, which means egress
// enforcement is that worker's job and the VMM worker must not also attach a
// policy to the device. The supervisor keeps Policy either way, for display
// and rollback.
type NetAttachment struct {
	Conn    net.Conn
	Split   bool
	Policy  *netpol.Policy
	Traffic *netpol.TrafficRecorder
}

// vmmWorkerSpawnHook, when set, rewrites the re-exec argv/env (tests only:
// os.Executable() is the test binary under `go test`).
var vmmWorkerSpawnHook func(argv *[]string, env *[]string)
