//go:build linux || darwin || windows

package vmmworker

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/ejpir/gantry/internal/workerproto"
)

type workerState struct {
	runner    Runner
	closeOnce sync.Once
	closeErr  error
	fds       *workerproto.FDMux
	policy    *netpol.Policy
	traffic   *netpol.TrafficRecorder
	vmDone    chan struct{}
	vmErr     error
}

func (state *workerState) run() {
	state.vmErr = state.runner.Run()
	if state.vmErr != nil {
		fmt.Fprintln(os.Stderr, "_vmm-worker: VM run:", state.vmErr)
	}
	close(state.vmDone)
}

func (state *workerState) setPolicy(request workerproto.Request) (any, error) {
	if state.policy == nil {
		return nil, fmt.Errorf("net.policy: no local netstack policy in this topology")
	}
	var body PolicyRequest
	if err := workerproto.DecodeBody(request, &body); err != nil {
		return nil, fmt.Errorf("net.policy: %w", err)
	}
	next, err := netpol.Parse(body.Policy)
	if err != nil {
		return nil, fmt.Errorf("net.policy: %w", err)
	}
	return nil, state.policy.Replace(next)
}

func (state *workerState) trafficSnapshot(workerproto.Request) (any, error) {
	if state.traffic == nil {
		return nil, fmt.Errorf("traffic.snapshot: no local netstack recorder in this topology")
	}
	return state.traffic.Snapshot(), nil
}

func (state *workerState) requestHotMemory(workerproto.Request) (any, error) {
	return nil, state.runner.RequestHotMemory()
}

func (state *workerState) capture(request workerproto.Request) (any, error) {
	if state.traffic == nil {
		return nil, fmt.Errorf("capture.read: no local netstack recorder in this topology")
	}
	var body packetcapture.Request
	if err := workerproto.DecodeBody(request, &body); err != nil {
		return nil, fmt.Errorf("capture.read: %w", err)
	}
	return state.traffic.Capture(body)
}

func forwardVsock(bridge *workerproto.Client, fds *workerproto.FDMux, port uint32) (net.Conn, error) {
	var token [workerproto.FDTokenLen]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	wait, err := fds.Expect(token)
	if err != nil {
		return nil, err
	}
	if err := bridge.Call("vsock.forward", ForwardRequest{
		Port:  port,
		Token: hex.EncodeToString(token[:]),
	}, nil); err != nil {
		wait.Cancel()
		return nil, err
	}
	file, err := wait.Wait(10 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("vsock.forward: %w", err)
	}
	conn, err := net.FileConn(file)
	_ = file.Close()
	return conn, err
}

func (state *workerState) wait(workerproto.Request) (any, error) {
	<-state.vmDone
	response := WaitResponse{}
	if state.vmErr != nil {
		response.Error = state.vmErr.Error()
	}
	if state.traffic != nil {
		snapshot := state.traffic.Snapshot()
		response.Traffic = &snapshot
	}
	return response, nil
}

func (state *workerState) closeRunner() error {
	state.closeOnce.Do(func() { state.closeErr = state.runner.Close() })
	return state.closeErr
}

func (state *workerState) closeVM(workerproto.Request) (any, error) {
	response := CloseResponse{}
	if err := state.closeRunner(); err != nil {
		response.Error = err.Error()
	}
	if state.traffic != nil {
		snapshot := state.traffic.Snapshot()
		response.Traffic = &snapshot
	}
	// Device-close failures must still terminate the worker after the final
	// response. The supervisor reports response.Error and escalates only if
	// the process then fails to exit.
	return response, workerproto.ErrShutdown
}

func (state *workerState) connectVsock(request workerproto.Request) (any, error) {
	var body ConnectRequest
	if err := workerproto.DecodeBody(request, &body); err != nil {
		return nil, fmt.Errorf("vsock.connect: %w", err)
	}
	decoded, err := hex.DecodeString(body.Token)
	if err != nil || len(decoded) != workerproto.FDTokenLen {
		return nil, fmt.Errorf("vsock.connect: bad token")
	}
	var token [workerproto.FDTokenLen]byte
	copy(token[:], decoded)
	file, err := state.fds.Recv(token)
	if err != nil {
		return nil, fmt.Errorf("vsock.connect: %w", err)
	}
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		return nil, fmt.Errorf("vsock.connect: %w", err)
	}
	if err := state.runner.InjectVsockConn(body.Port, conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("vsock.connect: %w", err)
	}
	return nil, nil
}
