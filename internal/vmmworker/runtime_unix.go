//go:build linux || darwin

package vmmworker

import (
	"fmt"
	"net"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/sharebroker"
	"github.com/ejpir/gantry/internal/shares"
	"github.com/ejpir/gantry/internal/virtio"
	"github.com/ejpir/gantry/internal/vmm"
	"github.com/ejpir/gantry/internal/workerconf"
	"github.com/ejpir/gantry/internal/workerproto"
)

// Runner is the prepared VM surface needed by the worker control plane.
type Runner interface {
	Run() error
	Close() error
	InjectVsockConn(guestPort uint32, conn net.Conn) error
}

// BootFunc prepares a VM from authenticated, pre-opened capabilities.
type BootFunc func(vmm.Opts) (Runner, error)

// Runtime contains the worker's explicit process-local dependencies. The
// production command uses NewRuntime; tests replace individual functions
// without mutable package globals.
type Runtime struct {
	Boot              BootFunc
	ApplyConfinement  func(workerconf.Spec) (*workerconf.Report, error)
	VerifyConfinement func(workerconf.Spec, *workerconf.Report)
}

// NewRuntime returns the production worker runtime.
func NewRuntime() Runtime {
	return Runtime{
		Boot:              boot,
		ApplyConfinement:  workerconf.Apply,
		VerifyConfinement: workerconf.Verify,
	}
}

type machineRunner struct{ machine *vmm.Machine }

func (r machineRunner) Run() error   { return vmm.Run(r.machine) }
func (r machineRunner) Close() error { return r.machine.Close() }
func (r machineRunner) InjectVsockConn(port uint32, conn net.Conn) error {
	return r.machine.InjectVsockConn(port, conn)
}

func boot(opts vmm.Opts) (Runner, error) {
	machine, err := vmm.Prepare(opts)
	if err != nil {
		return nil, err
	}
	return machineRunner{machine: machine}, nil
}

// Serve authenticates the bootstrap channels, applies confinement, boots the
// VM, and serves control requests until shutdown or channel failure.
func (rt Runtime) Serve(control, bridge, fdChannel net.Conn, load AssetLoader) error {
	if control == nil || bridge == nil || fdChannel == nil {
		return fmt.Errorf("vmm worker: nil bootstrap channel")
	}
	defer func() {
		_ = control.Close()
		_ = bridge.Close()
		_ = fdChannel.Close()
	}()
	if rt.Boot == nil || rt.ApplyConfinement == nil || rt.VerifyConfinement == nil {
		return fmt.Errorf("vmm worker: incomplete runtime")
	}
	if load == nil {
		return fmt.Errorf("vmm worker: nil asset loader")
	}

	var config Config
	nonce, err := workerproto.ServeHandshake(control, workerproto.RoleVMM, &config)
	if err != nil {
		return err
	}
	if err := config.validate(); err != nil {
		err = fmt.Errorf("boot config: %w", err)
		_ = workerproto.WriteMessage(control, BootAck{Error: err.Error()})
		return err
	}
	assets, err := load(config)
	defer assets.close()
	if err != nil {
		return fmt.Errorf("descriptor table: %w", err)
	}
	if assets.ShareConn == nil {
		return fmt.Errorf("descriptor table: share relay is required")
	}
	// Authenticate the independent data channels before processing an RPC or
	// guest frame. This catches cross-wired descriptor tables at launch.
	if err := workerproto.ReadNonce(fdChannel, nonce); err != nil {
		return fmt.Errorf("fd channel nonce: %w", err)
	}
	if err := workerproto.ReadNonce(assets.ShareConn, nonce); err != nil {
		return fmt.Errorf("share channel nonce: %w", err)
	}

	confinement, err := rt.confine(config, control, bridge, fdChannel, assets)
	if err != nil {
		return err
	}

	fds := workerproto.NewFDMux(fdChannel)
	defer func() { _ = fds.Close() }()
	bridgeClient := workerproto.NewClient(bridge)
	defer func() { _ = bridgeClient.Close() }()

	filesystem := vmm.Filesystem{Tag: shares.HubTag}
	if config.VhostShares {
		confinement.Notes = append(confinement.Notes, "virtio-fs data plane uses shared guest RAM and doorbell pipes; VMM retains no host share roots")
		queues := make([]virtio.VhostQueueFiles, len(assets.VhostQueue))
		for index, queue := range assets.VhostQueue {
			queues[index] = virtio.VhostQueueFiles{
				KickRead: queue.KickRead, KickWrite: queue.KickWrite,
				CallRead: queue.CallRead, CallWrite: queue.CallWrite,
			}
		}
		endpoint, endpointErr := virtio.NewVhostEndpoint(assets.ShareConn, queues)
		if endpointErr != nil {
			return endpointErr
		}
		defer func() { _ = endpoint.Close() }()
		assets.ShareConn = nil
		assets.VhostQueue = nil
		filesystem.Vhost = endpoint
		filesystem.Description = "vhost shared-memory share backend"
	} else {
		shareClient, clientErr := sharebroker.NewClient(assets.ShareConn)
		if clientErr != nil {
			return fmt.Errorf("share proxy: %w", clientErr)
		}
		defer func() { _ = shareClient.Close() }()
		filesystem.Handler = shareClient
		filesystem.Description = "supervisor share broker (hot-add enabled)"
	}

	policy, traffic, err := workerNetworkState(config.Policy)
	if err != nil {
		return err
	}
	if traffic != nil {
		defer traffic.Close()
	}

	var bootStart time.Time
	if config.BootTimingStartUnixNano != 0 {
		bootStart = time.Unix(0, config.BootTimingStartUnixNano)
	}
	netPolicy, netTraffic := netDeviceHooks(policy, traffic)
	sharedRAM := assets.SharedRAM
	if config.VhostShares {
		// Prepare consumes every descriptor-bearing option on entry.
		assets.SharedRAM = nil
	}
	runner, err := rt.Boot(vmm.Opts{
		MemSize:         config.MemSize,
		Kernel:          assets.Kernel,
		Rootfs:          assets.Rootfs,
		DisksRO:         assets.DisksRO,
		Disks:           assets.Disks,
		DisksPrelocked:  config.DisksPrelocked,
		SharedRAM:       sharedRAM,
		Filesystems:     []vmm.Filesystem{filesystem},
		NetConn:         assets.NetConn,
		NetMAC:          config.NetMAC,
		NetPolicy:       netPolicy,
		NetTraffic:      netTraffic,
		KVM:             assets.KVM,
		GuestCID:        config.GuestCID,
		VCPUs:           config.VCPUs,
		Cmdline:         config.Cmdline,
		Console:         assets.Console,
		BootTimingStart: bootStart,
		VsockDial: func(port uint32) (net.Conn, error) {
			return forwardVsock(bridgeClient, fds, port)
		},
		VsockNoListen: true,
	})
	if err != nil {
		_ = workerproto.WriteMessage(control, BootAck{Error: err.Error(), Confinement: confinement})
		return err
	}
	state := &workerState{
		runner:  runner,
		fds:     fds,
		policy:  policy,
		traffic: traffic,
		vmDone:  make(chan struct{}),
	}
	defer func() { _ = state.closeRunner() }()
	if err := workerproto.WriteMessage(control, BootAck{OK: true, Confinement: confinement}); err != nil {
		return fmt.Errorf("boot ack: %w", err)
	}
	go state.run()

	return workerproto.ServeRequests(control, map[string]workerproto.Handler{
		"vm.wait":          state.wait,
		"vm.close":         state.closeVM,
		"vsock.connect":    state.connectVsock,
		"net.policy":       state.setPolicy,
		"traffic.snapshot": state.trafficSnapshot,
		"shutdown": func(workerproto.Request) (any, error) {
			return nil, workerproto.ErrShutdown
		},
	})
}

// netDeviceHooks converts the worker's concrete network state into the
// device-level interfaces vmm.Opts carries. The conversion is explicit
// because a direct assignment of a nil *netpol.Policy yields a NON-nil
// interface holding a nil pointer: virtio-net's `policy != nil` guard then
// passes and the first inbound frame dereferences it. That is the normal
// state in split-net topology, where the network worker owns enforcement
// and no policy is sent to the VMM worker at all.
func netDeviceHooks(policy *netpol.Policy, traffic *netpol.TrafficRecorder) (virtio.PacketPolicy, virtio.TrafficObserver) {
	var (
		devicePolicy  virtio.PacketPolicy
		deviceTraffic virtio.TrafficObserver
	)
	if policy != nil {
		devicePolicy = policy
	}
	if traffic != nil {
		deviceTraffic = traffic
	}
	return devicePolicy, deviceTraffic
}

func workerNetworkState(rawPolicy []byte) (*netpol.Policy, *netpol.TrafficRecorder, error) {
	if len(rawPolicy) == 0 {
		return nil, nil, nil
	}
	policy, err := netpol.Parse(rawPolicy)
	if err != nil {
		return nil, nil, fmt.Errorf("network policy: %w", err)
	}
	return policy, netpol.NewTrafficRecorder(""), nil
}
