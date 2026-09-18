package guestplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/sandbox/supervisor"
	"github.com/ejpir/gantry/internal/sandbox/vmmworker"
	"github.com/ejpir/gantry/internal/vmm"
	"github.com/ejpir/gantry/internal/workerconf"

	"github.com/containerd/ttrpc"
)

// Runner is the non-owning split-VMM capability. Close and Wait remain on the
// concrete runner held only by Plane.
type Runner interface {
	RequestHotMemory() error
	Done() <-chan struct{}
	Err() error
	DialStream(uint32) (net.Conn, error)
}

// RPC is the non-owning guest session capability.
type RPC interface {
	Session(client.SessionOptions, io.Reader, io.Writer) error
}

// PacketCapture is the optional split-runner capture capability.
type PacketCapture interface {
	Capture(packetcapture.Request) (packetcapture.Snapshot, error)
}

type runnerView struct{ runner vmmworker.Runner }

func (v runnerView) RequestHotMemory() error { return v.runner.RequestHotMemory() }
func (v runnerView) Done() <-chan struct{}   { return v.runner.Done() }
func (v runnerView) Err() error              { return v.runner.Err() }
func (v runnerView) DialStream(port uint32) (net.Conn, error) {
	return v.runner.DialStream(port)
}

type policyPusherView struct{ pusher control.VMMPolicyPusher }

func (v policyPusherView) SetPolicy(policy *netpol.Policy) error {
	return v.pusher.SetPolicy(policy)
}

type packetCaptureView struct{ capture PacketCapture }

func (v packetCaptureView) Capture(request packetcapture.Request) (packetcapture.Snapshot, error) {
	return v.capture.Capture(request)
}

type rpcView struct{ client *ttrpc.Client }

func (c rpcView) Session(options client.SessionOptions, stdin io.Reader, stdout io.Writer) error {
	return client.Session(c.client, options, stdin, stdout)
}

// Plane exclusively owns VMM execution, the guest RPC transport, and the
// guest-exit notification task.
type Plane struct {
	mu sync.RWMutex

	runner  vmmworker.Runner
	machine *vmm.Machine
	rpc     *ttrpc.Client
	exit    <-chan error

	workers          supervisor.BackgroundGroup
	devicesCloseOnce sync.Once
	devicesCloseErr  error
	closeOnce        sync.Once
	closeErr         error
}

func (g *Plane) SetRunner(runner vmmworker.Runner) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.runner = runner
}

func (g *Plane) SetMachine(machine *vmm.Machine) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.machine = machine
}

func (g *Plane) SetRPC(rpc *ttrpc.Client) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rpc = rpc
}

func (g *Plane) Runner() Runner {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.runner == nil {
		return nil
	}
	return runnerView{runner: g.runner}
}

func (g *Plane) PolicyPusher() control.VMMPolicyPusher {
	g.mu.RLock()
	defer g.mu.RUnlock()
	pusher, ok := g.runner.(control.VMMPolicyPusher)
	if !ok {
		return nil
	}
	return policyPusherView{pusher: pusher}
}

func (g *Plane) PacketCapture() PacketCapture {
	g.mu.RLock()
	defer g.mu.RUnlock()
	capture, ok := g.runner.(PacketCapture)
	if !ok {
		return nil
	}
	return packetCaptureView{capture: capture}
}

func (g *Plane) ConfinementReport() (*workerconf.Report, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	reporter, ok := g.runner.(interface{ ConfinementReport() workerconf.Report })
	if !ok {
		return nil, false
	}
	report := reporter.ConfinementReport()
	return &report, true
}

func (g *Plane) RPC() RPC {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.rpc == nil {
		return nil
	}
	return rpcView{client: g.rpc}
}

func (g *Plane) Start() <-chan error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.exit != nil {
		return g.exit
	}
	exited := make(chan error, 1)
	runner, machine := g.runner, g.machine
	if !g.workers.Start(func(context.Context) {
		if runner != nil {
			exited <- runner.Wait()
			return
		}
		exited <- vmm.Run(machine)
	}) {
		close(exited)
	}
	g.exit = exited
	return exited
}

// StartTask admits a guest-lifetime task, used for the one-shot RPC accept.
func (g *Plane) StartTask(run func(context.Context)) bool { return g.workers.Start(run) }

func (g *Plane) Exited() <-chan error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.exit
}

func (g *Plane) Sync(timeout time.Duration) error {
	g.mu.RLock()
	rpc := g.rpc
	g.mu.RUnlock()
	if rpc == nil {
		return fmt.Errorf("guest RPC unavailable")
	}
	return client.SyncGuest(rpc, timeout)
}

func (g *Plane) MultiContainerSpike(options client.SpikeOptions) error {
	g.mu.RLock()
	rpc := g.rpc
	g.mu.RUnlock()
	if rpc == nil {
		return fmt.Errorf("guest RPC unavailable")
	}
	return client.MultiContainerSpike(rpc, options)
}

func (g *Plane) RootfsSpike(options client.RootfsSpikeOptions) (*client.RootfsSpikeResult, error) {
	g.mu.RLock()
	rpc := g.rpc
	g.mu.RUnlock()
	if rpc == nil {
		return nil, fmt.Errorf("guest RPC unavailable")
	}
	return client.RootfsSpike(rpc, options)
}

func (g *Plane) RequestHotMemory() error {
	g.mu.RLock()
	runner, machine := g.runner, g.machine
	g.mu.RUnlock()
	if runner != nil {
		return runner.RequestHotMemory()
	}
	if machine != nil {
		return machine.RequestHotMemory()
	}
	return nil
}

func (g *Plane) CloseDevices() error {
	g.devicesCloseOnce.Do(func() {
		g.mu.RLock()
		runner, machine := g.runner, g.machine
		g.mu.RUnlock()
		if runner != nil {
			g.devicesCloseErr = runner.Close()
		} else if machine != nil {
			g.devicesCloseErr = machine.Close()
		}
	})
	return g.devicesCloseErr
}

func (g *Plane) Close() error {
	g.closeOnce.Do(func() {
		g.mu.RLock()
		rpc := g.rpc
		g.mu.RUnlock()
		var result error
		if rpc != nil {
			result = errors.Join(result, rpc.Close())
		}
		result = errors.Join(result, g.CloseDevices())
		g.workers.Close()
		g.closeErr = result
	})
	return g.closeErr
}

var _ Runner = runnerView{}
