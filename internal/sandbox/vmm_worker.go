//go:build linux || darwin || windows

package sandbox

// Trusted supervisor handle for the untrusted VMM worker. Process creation,
// host socket brokering, policy ownership, and lifecycle decisions remain in
// sandbox; guest execution and RPC handlers live in internal/vmmworker.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/ejpir/gantry/internal/sharebroker"
	"github.com/ejpir/gantry/internal/sharefs"
	"github.com/ejpir/gantry/internal/vmmworker"
	"github.com/ejpir/gantry/internal/workerconf"
	"github.com/ejpir/gantry/internal/workerproto"
)

// ------------------------------------------------------------ supervisor

// vmmWorker is the supervisor's handle on the worker process: control
// client, fd channel (send side), bridge serve loop, and lifecycle. It
// implements vmmRunner.
type vmmWorker struct {
	proc           *os.Process
	client         *workerproto.Client // control (fd 3)
	fdChan         net.Conn            // fd 5, send side
	fdSend         sync.Mutex          // serialize SCM_RIGHTS sends
	bridge         net.Conn
	bridgeE        chan error
	share          net.Conn // fd 6 peer: supervisor side of the FUSE relay
	shareE         chan error
	diagnostics    *boundedLogPipe
	diagnosticPath string
	containment    workerContainment
	diskLocks      []*os.File
	revokeOnce     sync.Once
	revokeErr      error
	lifecycle      *workerLifecycle
	waitMu         sync.Mutex // protects lazy lifecycle-context initialization
	waitCtx        context.Context
	waitCancel     context.CancelFunc
	// Local-netstack counters live in the confined worker. Periodic pulls
	// are cancellable; vm.wait/vm.close responses furnish the final snapshot
	// before the control channel dies.
	trafficEpoch    *netpol.TrafficEpoch
	trafficCancel   context.CancelFunc
	trafficDone     chan struct{}
	trafficStopOnce sync.Once

	closeOnce sync.Once
	closeErr  error

	confReport workerconf.Report // from the boot ack
}

// Done closes when the worker process is reaped (Err reports how).
func (w *vmmWorker) Done() <-chan struct{} { return w.lifecycle.Done() }

// Err reports the worker's exit state after Done closes.
func (w *vmmWorker) Err() error { return w.lifecycle.Err() }

func (w *vmmWorker) setDead(err error) {
	err = errors.Join(err, w.revokeWorkerCapabilities())
	if err != nil && w.diagnosticPath != "" {
		err = errors.Join(err, workerDiagnosticTail("vmm-worker", w.diagnosticPath))
	}
	// Publish death before closing the relay so the broker goroutine can
	// distinguish process teardown from an independent protocol failure.
	w.lifecycle.Exit(err)
	if w.share != nil {
		_ = w.share.Close()
	}
	w.cancelWait()
}

func (w *vmmWorker) revokeWorkerCapabilities() error {
	w.revokeOnce.Do(func() {
		if w.containment != nil {
			w.revokeErr = errors.Join(w.revokeErr, w.containment.Close())
			w.containment = nil
		}
		if w.diagnostics != nil {
			w.revokeErr = errors.Join(w.revokeErr, w.diagnostics.Close())
		}
		for _, lock := range w.diskLocks {
			if lock != nil {
				w.revokeErr = errors.Join(w.revokeErr, lock.Close())
			}
		}
		w.diskLocks = nil
	})
	return w.revokeErr
}

func (w *vmmWorker) markStopping() {
	if w != nil && w.lifecycle != nil {
		w.lifecycle.BeginStop()
	}
}

func (w *vmmWorker) waitContext() context.Context {
	w.waitMu.Lock()
	defer w.waitMu.Unlock()
	if w.waitCtx == nil {
		w.waitCtx, w.waitCancel = context.WithCancel(context.Background())
	}
	return w.waitCtx
}

func (w *vmmWorker) cancelWait() {
	if w == nil {
		return
	}
	w.waitMu.Lock()
	if w.waitCtx == nil {
		w.waitCtx, w.waitCancel = context.WithCancel(context.Background())
	}
	cancel := w.waitCancel
	w.waitMu.Unlock()
	cancel()
}

const workerTrafficSyncInterval = 2 * time.Second

func (w *vmmWorker) startTrafficSync(rec *netpol.TrafficRecorder) {
	w.startTrafficSyncEvery(rec, workerTrafficSyncInterval)
}

// startTrafficSyncEvery exists so the short-lived-worker regression can
// choose an interval that provably cannot tick during the test.
func (w *vmmWorker) startTrafficSyncEvery(rec *netpol.TrafficRecorder, interval time.Duration) {
	if w == nil || rec == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.trafficEpoch = rec.BeginEpoch()
	w.trafficCancel = cancel
	w.trafficDone = make(chan struct{})
	go syncWorkerTraffic(ctx, w, w.trafficEpoch, interval, w.trafficDone)
}

func (w *vmmWorker) stopTrafficSync() {
	if w == nil {
		return
	}
	w.trafficStopOnce.Do(func() {
		if w.trafficCancel != nil {
			w.trafficCancel()
		}
		if w.trafficDone != nil {
			<-w.trafficDone
		}
	})
}

func (w *vmmWorker) mergeFinalTraffic(snapshot *netpol.TrafficSnapshot) {
	w.stopTrafficSync()
	if w != nil && w.trafficEpoch != nil && snapshot != nil {
		w.trafficEpoch.Merge(*snapshot)
	}
}

// startShareBroker connects the worker's virtio-fs proxy to the
// supervisor-owned hub. FUSE requests flow to the supervisor; watcher-driven
// invalidations flow back over the same authenticated stream. The hub remains the sole owner of host paths,
// pinned directory descriptors, and Windows directory handles.
func (w *vmmWorker) startShareBroker(hub *sharefs.Hub) error {
	if w == nil || w.share == nil {
		return fmt.Errorf("share relay unavailable")
	}
	if hub == nil {
		return fmt.Errorf("share hub unavailable")
	}
	if w.shareE != nil {
		return fmt.Errorf("share broker already started")
	}
	w.shareE = make(chan error, 1)
	go w.monitorShareServe(func() error { return sharebroker.Serve(w.share, hub) }, "share broker", true)
	return nil
}

func (w *vmmWorker) monitorShareServe(serve func() error, label string, closeImmediately bool) {
	err := serve()
	select {
	case <-w.lifecycle.Stopping():
		return
	case <-w.Done():
		return
	default:
	}
	if err == nil {
		err = fmt.Errorf("%s closed unexpectedly", label)
	} else {
		err = fmt.Errorf("%s: %w", label, err)
	}
	w.shareE <- err
	// A broker failure is independently fatal. A vhost control EOF, however,
	// normally follows Machine.Run returning and closing its frontend. Give
	// vm.wait a brief chance to publish that primary hypervisor error instead
	// of masking it with the secondary control-channel EOF.
	if !closeImmediately {
		timer := time.NewTimer(500 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-w.lifecycle.Stopping():
			return
		case <-w.Done():
			return
		case <-timer.C:
		}
	}
	// FUSE operations are stateful and may mutate the host. Never reconnect
	// or replay after a truncated/malformed exchange.
	_ = w.Close()
}

// Wait parks until the guest exits (the split-mode guestErr).
func (w *vmmWorker) Wait() error {
	ctx := w.waitContext()
	var out vmmworker.WaitResponse
	if err := w.client.CallContext(ctx, "vm.wait", nil, &out); err != nil {
		if errors.Is(err, context.Canceled) {
			// An unexpected share-relay failure initiates Close. Prefer its
			// actionable cause over the lifecycle cancellation it triggered.
			select {
			case shareErr := <-w.shareE:
				if shareErr == nil {
					shareErr = fmt.Errorf("share broker: share relay closed unexpectedly")
				}
				return shareErr
			default:
			}
			// setDead publishes the process result and closes Done before it
			// cancels this call, so a death-triggered cancellation retains
			// the authoritative process error.
			select {
			case <-w.Done():
				return w.Err()
			default:
			}
		}
		return err
	}
	w.mergeFinalTraffic(out.Traffic)
	if out.Error != "" {
		return fmt.Errorf("%s", out.Error)
	}
	return nil
}

// Close asks the worker to flush devices and exit, escalating to SIGKILL.
// Idempotent: teardown paths may stack (explicit stop + defer).
func (w *vmmWorker) Close() error {
	w.closeOnce.Do(func() {
		var shutdownErr error
		// vm.wait is deliberately unbounded during normal operation. Stop
		// it synchronously before beginning the bounded shutdown RPC.
		w.cancelWait()
		w.markStopping()
		w.stopTrafficSync()
		if w.client != nil {
			var out vmmworker.CloseResponse
			if err := w.client.CallWithTimeout("vm.close", nil, &out, 15*time.Second); err != nil {
				shutdownErr = errors.Join(shutdownErr, fmt.Errorf("vmm worker device shutdown: %w", err))
			} else {
				w.mergeFinalTraffic(out.Traffic)
				if out.Error != "" {
					shutdownErr = errors.Join(shutdownErr, fmt.Errorf("vmm worker device shutdown: %s", out.Error))
				}
			}
			_ = w.client.Close()
		}
		// A relay-triggered Close carries its original protocol cause here.
		// During an intentional shutdown the broker observes Stopping and does
		// not publish an error.
		if w.shareE != nil {
			select {
			case err := <-w.shareE:
				shutdownErr = errors.Join(shutdownErr, err)
			default:
			}
		}
		if w.bridge != nil {
			_ = w.bridge.Close()
		}
		if w.fdChan != nil {
			_ = w.fdChan.Close()
		}
		if w.share != nil {
			_ = w.share.Close()
		}
		var kill func() error
		if w.proc != nil {
			kill = w.proc.Kill
		}
		w.closeErr = errors.Join(shutdownErr, w.lifecycle.WaitExit(5*time.Second, kill))
	})
	return w.closeErr
}

func (w *vmmWorker) RequestHotMemory() error {
	return w.client.Call("vm.hot-memory", nil, nil)
}

// TrafficSnapshot pulls the worker's in-memory enforcement counters
// (local-netstack topology only).
func (w *vmmWorker) TrafficSnapshot() (netpol.TrafficSnapshot, error) {
	var snap netpol.TrafficSnapshot
	err := w.client.Call("traffic.snapshot", struct{}{}, &snap)
	return snap, err
}

func (w *vmmWorker) trafficSnapshotContext(ctx context.Context) (netpol.TrafficSnapshot, error) {
	var snap netpol.TrafficSnapshot
	err := w.client.CallContext(ctx, "traffic.snapshot", struct{}{}, &snap)
	return snap, err
}

func (w *vmmWorker) Capture(request packetcapture.Request) (packetcapture.Snapshot, error) {
	var snapshot packetcapture.Snapshot
	err := w.client.Call("capture.read", request, &snapshot)
	return snapshot, err
}

// SetPolicy pushes a live egress-policy swap to the worker (local-
// netstack topology only; the split-net topology uses the net-worker's
// prepare/commit RPCs instead).
func (w *vmmWorker) SetPolicy(policy *netpol.Policy) error {
	raw, err := netpol.Marshal(policy)
	if err != nil {
		return err
	}
	return w.client.Call("net.policy", vmmworker.PolicyRequest{Policy: raw}, nil)
}

// ConfinementReport returns the worker's confinement report as carried
// by the boot ack (platform-neutral via a method so shared files never
// name the unix-only concrete type in field positions).
func (w *vmmWorker) ConfinementReport() workerconf.Report { return w.confReport }

// sendFD serializes a token-correlated descriptor transfer.
func (w *vmmWorker) sendFD(token [workerproto.FDTokenLen]byte, f *os.File) error {
	w.fdSend.Lock()
	defer w.fdSend.Unlock()
	if err := workerproto.SendFD(w.fdChan, token, f); err != nil {
		// The dedicated descriptor relationship is no longer trustworthy.
		// Closing control makes the worker unwind instead of leaving a
		// partially functional VM whose future transfers repeatedly stall.
		_ = w.fdChan.Close()
		if w.client != nil {
			_ = w.client.Close()
		}
		return err
	}
	return nil
}

// DialStream opens a host->guest stream to the guest's listening port:
// a fresh socketpair, one end transferred to the worker, the other
// returned for the broker's session protocol.
func (w *vmmWorker) DialStream(guestPort uint32) (net.Conn, error) {
	sup, wrk, err := socketpairConns()
	if err != nil {
		return nil, err
	}
	wrkFile, err := connFile(wrk)
	_ = wrk.Close()
	if err != nil {
		_ = sup.Close()
		return nil, err
	}
	var token [workerproto.FDTokenLen]byte
	if _, err := rand.Read(token[:]); err != nil {
		_ = sup.Close()
		_ = wrkFile.Close()
		return nil, err
	}
	// The descriptor goes first (the worker's handler blocks on Recv
	// before answering); a dead worker surfaces as a send error.
	if err := w.sendFD(token, wrkFile); err != nil {
		_ = sup.Close()
		_ = wrkFile.Close()
		return nil, fmt.Errorf("vsock.connect: %w", err)
	}
	_ = wrkFile.Close()
	err = w.client.Call("vsock.connect", vmmworker.ConnectRequest{Port: guestPort, Token: hex.EncodeToString(token[:])}, nil)
	if err != nil {
		_ = sup.Close()
		return nil, fmt.Errorf("vsock.connect: %w", err)
	}
	return sup, nil
}
