package sandbox

// This file is the trusted supervisor half of the split network worker. The
// child runtime and RPC handlers live in internal/networkworker.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/networkworker"
	"github.com/ejpir/gantry/internal/vnet"
	"github.com/ejpir/gantry/internal/workerconf"
	"github.com/ejpir/gantry/internal/workerproto"
)

// netWorker is the supervisor's handle on the spawned worker process and
// implements NetworkBackend over RPC.
type netWorker struct {
	cmd            *os.Process // nil when driven in-process (tests)
	client         *workerproto.Client
	data           net.Conn
	gen            uint64
	kill           func() error
	policyMu       sync.Mutex // serializes each complete policy transaction
	portMu         sync.Mutex // serializes each complete port transaction
	conf           *workerconf.Report
	diagnostics    *boundedLogPipe
	diagnosticOnce sync.Once
	diagnosticErr  error

	trafficEpoch    *netpol.TrafficEpoch
	trafficCancel   context.CancelFunc
	trafficDone     chan struct{}
	trafficStopOnce sync.Once

	lifecycle *workerLifecycle

	closeOnce sync.Once
	closeErr  error
}

// Done closes when the worker process is reaped. The daemon treats an early
// close as fatal to the sandbox: a network-worker exit is never survivable
// in-place. Err reports the exit cause without consuming the notification.
func (w *netWorker) Done() <-chan struct{} { return w.lifecycle.Done() }

// Err reports the worker's exit state after Done closes.
func (w *netWorker) Err() error { return w.lifecycle.Err() }

func (w *netWorker) setDead(err error) {
	w.diagnosticOnce.Do(func() {
		if w.diagnostics != nil {
			w.diagnosticErr = w.diagnostics.Close()
		}
	})
	err = errors.Join(err, w.diagnosticErr)
	w.lifecycle.Exit(err)
}

func (w *netWorker) ConfinementReport() *workerconf.Report {
	if w == nil || w.conf == nil {
		return nil
	}
	report := *w.conf
	report.Results = append([]workerconf.PropertyResult(nil), w.conf.Results...)
	report.Notes = append([]string(nil), w.conf.Notes...)
	return &report
}

const networkWorkerTrafficSyncInterval = 2 * time.Second

func (w *netWorker) startTrafficSync(recorder *netpol.TrafficRecorder) {
	w.startTrafficSyncEvery(recorder, networkWorkerTrafficSyncInterval)
}

func (w *netWorker) startTrafficSyncEvery(recorder *netpol.TrafficRecorder, interval time.Duration) {
	if w == nil || recorder == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.trafficEpoch = recorder.BeginEpoch()
	w.trafficCancel = cancel
	w.trafficDone = make(chan struct{})
	go w.syncTraffic(ctx, interval)
}

func (w *netWorker) syncTraffic(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer func() {
		ticker.Stop()
		close(w.trafficDone)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.Done():
			return
		case <-ticker.C:
			if snapshot, err := w.trafficSnapshotContext(ctx); err == nil {
				w.trafficEpoch.Merge(snapshot)
			}
		}
	}
}

func (w *netWorker) stopTrafficSync() {
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

func (w *netWorker) mergeFinalTraffic(snapshot *netpol.TrafficSnapshot) {
	w.stopTrafficSync()
	if w != nil && w.trafficEpoch != nil && snapshot != nil {
		w.trafficEpoch.Merge(*snapshot)
	}
}

// startNetWorker spawns the worker process, performs the handshake and
// nonce cross-check, and returns the ready backend plus the supervisor
// end of the data channel (which the virtio-net device attaches to).
func startNetWorker(cfg networkworker.Config, workdir string) (*netWorker, net.Conn, error) {
	// The worker's stderr lands next to its traffic log: bootstrap
	// failures leave their own postmortem (worker-net.log).
	ctrlSup, dataSup, cmd, diagnostics, err := spawnNetWorkerProcess(
		filepath.Join(workdir, "worker-net.log"), cfg.Confinement)
	if err != nil {
		return nil, nil, err
	}
	w := &netWorker{cmd: cmd, data: dataSup, diagnostics: diagnostics, lifecycle: newWorkerLifecycle()}
	if cmd != nil {
		w.kill = func() error { return cmd.Kill() }
		go func() { w.setDead(waitProcess(cmd, "net-worker")) }()
	}
	fail := func(err error) (*netWorker, net.Conn, error) {
		_ = ctrlSup.Close()
		_ = dataSup.Close()
		if w.kill != nil {
			_ = w.kill()
		}
		return nil, nil, err
	}
	nonce, err := workerproto.NewNonce()
	if err != nil {
		return fail(fmt.Errorf("net-worker nonce: %w", err))
	}
	if err := workerproto.SendHandshake(ctrlSup, workerproto.RoleNet, nonce, cfg); err != nil {
		return fail(fmt.Errorf("net-worker handshake: %w", err))
	}
	if err := workerproto.WriteNonce(dataSup, nonce); err != nil {
		return fail(fmt.Errorf("net-worker nonce: %w", err))
	}
	var ack networkworker.BootAck
	_ = ctrlSup.SetReadDeadline(time.Now().Add(15 * time.Second))
	if err := workerproto.ReadMessage(ctrlSup, &ack); err != nil {
		return fail(fmt.Errorf("net-worker ready: %w", err))
	}
	_ = ctrlSup.SetReadDeadline(time.Time{})
	if !ack.OK {
		if ack.Error == "" {
			ack.Error = "worker refused bootstrap"
		}
		return fail(fmt.Errorf("net-worker bootstrap failed: %s", ack.Error))
	}
	if ack.Confinement == nil || ack.Confinement.Platform != runtime.GOOS ||
		ack.Confinement.Mode != cfg.Confinement {
		return fail(fmt.Errorf("net-worker bootstrap failed: invalid confinement report for %s/%s",
			runtime.GOOS, cfg.Confinement))
	}
	if cfg.Confinement == "required" {
		if failed := ack.Confinement.Failed(
			networkworker.RequiredConfinementProperties(runtime.GOOS)...); len(failed) != 0 {
			return fail(fmt.Errorf("net-worker bootstrap failed: required confinement not enforced: %v", failed))
		}
	}
	// Start the Client read loop only after consuming the unsolicited boot
	// acknowledgement. Otherwise it races this explicit read and can leave
	// the supervisor waiting for an acknowledgement it already consumed.
	w.client = workerproto.NewClient(ctrlSup)
	w.conf = ack.Confinement
	return w, dataSup, nil
}

// SetPolicy runs an idempotent prepare+commit transaction. The complete
// exchange is supervisor-serialized; generation advances only after a commit
// response or status readback proves that exact transaction committed.
func (w *netWorker) SetPolicy(policy *netpol.Policy) error {
	raw, err := netpol.Marshal(policy)
	if err != nil {
		return err
	}
	w.policyMu.Lock()
	defer w.policyMu.Unlock()

	if err := w.syncPolicyState(); err != nil {
		return fmt.Errorf("policy status: %w", err)
	}
	gen := w.gen + 1
	nonce, err := workerproto.NewNonce()
	if err != nil {
		return fmt.Errorf("policy transaction nonce: %w", err)
	}
	txn := hex.EncodeToString(nonce)
	prepare := networkworker.PolicyPrepareRequest{Generation: gen, Transaction: txn, Policy: raw}
	if err := w.client.Call(networkworker.OpPolicyPrepare, prepare, nil); err != nil {
		// A timeout can lose the response after prepare succeeded. Read the
		// transaction state before deciding whether the active policy changed.
		status, statusErr := w.readPolicyStatus(txn)
		if statusErr != nil {
			return errors.Join(fmt.Errorf("policy prepare: %w", err),
				fmt.Errorf("policy status after prepare: %w", statusErr))
		}
		w.gen = status.Generation
		switch status.State {
		case networkworker.PolicyStateCommitted:
			return nil
		case networkworker.PolicyStatePrepared:
			// Continue with the same transaction ID and generation.
		default:
			return fmt.Errorf("policy prepare: %w", err)
		}
	}
	return w.commitPolicyTransaction(gen, txn)
}

// syncPolicyState reconciles the supervisor generation with the worker and
// clears a prepared transaction left by a prior failed call. Preparation does
// not mutate the active policy, so aborting it preserves failure atomicity.
func (w *netWorker) syncPolicyState() error {
	status, err := w.readPolicyStatus("")
	if err != nil {
		return err
	}
	w.gen = status.Generation
	if status.PendingTransaction == "" {
		return nil
	}
	abort := networkworker.PolicyGenerationRequest{
		Generation: status.PendingGeneration, Transaction: status.PendingTransaction,
	}
	if err := w.client.Call(networkworker.OpPolicyAbort, abort, nil); err != nil {
		after, statusErr := w.readPolicyStatus("")
		if statusErr == nil {
			w.gen = after.Generation
			if after.PendingTransaction == "" {
				return nil // abort response was lost
			}
		}
		return errors.Join(fmt.Errorf("abort stale policy transaction: %w", err), statusErr)
	}
	return nil
}

func (w *netWorker) readPolicyStatus(transaction string) (networkworker.PolicyStatusResponse, error) {
	var status networkworker.PolicyStatusResponse
	err := w.client.Call(networkworker.OpPolicyStatus, networkworker.PolicyGenerationRequest{Transaction: transaction}, &status)
	return status, err
}

func (w *netWorker) commitPolicyTransaction(gen uint64, txn string) error {
	req := networkworker.PolicyGenerationRequest{Generation: gen, Transaction: txn}
	var failures []error
	var lastStatus networkworker.PolicyStatusResponse
	haveStatus := false
	for attempt := 0; attempt < 2; attempt++ {
		if err := w.client.Call(networkworker.OpPolicyCommit, req, nil); err == nil {
			w.gen = gen
			return nil
		} else {
			failures = append(failures, fmt.Errorf("policy commit: %w", err))
		}
		status, err := w.readPolicyStatus(txn)
		if err != nil {
			failures = append(failures, fmt.Errorf("policy status after commit: %w", err))
			continue
		}
		lastStatus = status
		haveStatus = true
		w.gen = status.Generation
		switch status.State {
		case networkworker.PolicyStateCommitted:
			return nil // commit response was lost
		case networkworker.PolicyStatePrepared:
			continue // retry the same idempotent commit
		case networkworker.PolicyStateUnknown:
			if status.Generation < gen {
				return errors.Join(failures...) // previous policy is still active
			}
			return w.stopAfterAmbiguousPolicy(errors.Join(failures...))
		default:
			return w.stopAfterAmbiguousPolicy(errors.Join(failures...))
		}
	}

	if haveStatus && lastStatus.State == networkworker.PolicyStatePrepared {
		// Both commit attempts failed before applying. An acknowledged abort
		// normally proves the previous generation remains active. Decode its
		// status as well: a commit response and its immediate status response
		// can both be lost even though the commit applied, in which case abort
		// is an idempotent readback of the committed transaction.
		var status networkworker.PolicyStatusResponse
		if err := w.client.Call(networkworker.OpPolicyAbort, req, &status); err != nil {
			failures = append(failures, fmt.Errorf("abort failed policy transaction: %w", err))
			var statusErr error
			status, statusErr = w.readPolicyStatus(txn)
			if statusErr != nil {
				failures = append(failures, fmt.Errorf("policy status after abort: %w", statusErr))
				return w.stopAfterAmbiguousPolicy(errors.Join(failures...))
			}
		}
		w.gen = status.Generation
		switch {
		case status.State == networkworker.PolicyStateCommitted:
			return nil
		case status.State == networkworker.PolicyStateUnknown && status.Generation < gen:
			return errors.Join(failures...)
		default:
			failures = append(failures, fmt.Errorf(
				"policy transaction %q remained %s after abort (generation %d)",
				txn, status.State, status.Generation))
			return w.stopAfterAmbiguousPolicy(errors.Join(failures...))
		}
	}
	return w.stopAfterAmbiguousPolicy(errors.Join(failures...))
}

// stopAfterAmbiguousPolicy fails closed. If neither commit nor status replies,
// the supervisor cannot honestly claim which policy the worker enforces; the
// sandbox lifecycle will observe worker death and terminate instead of running
// with divergent control-plane state.
func (w *netWorker) stopAfterAmbiguousPolicy(cause error) error {
	stopErr := w.Close()
	return errors.Join(cause, fmt.Errorf("network policy state ambiguous; network worker stopped"), stopErr)
}

func (w *netWorker) Publish(proto, local, remote string) error {
	txn, err := newWorkerTransactionID()
	if err != nil {
		return fmt.Errorf("port transaction nonce: %w", err)
	}
	request := networkworker.PortPublishRequest{
		Transaction: txn,
		Proto:       proto,
		Local:       local,
		Remote:      remote,
	}
	return w.applyPortMutation(networkworker.OpPortPublish, txn, request, vnet.Forward{
		Protocol: proto,
		Local:    local,
		Remote:   remote,
	}, true)
}

func (w *netWorker) Unpublish(proto, local string) error {
	txn, err := newWorkerTransactionID()
	if err != nil {
		return fmt.Errorf("port transaction nonce: %w", err)
	}
	request := networkworker.PortUnpublishRequest{
		Transaction: txn,
		Proto:       proto,
		Local:       local,
	}
	return w.applyPortMutation(networkworker.OpPortUnpublish, txn, request, vnet.Forward{
		Protocol: proto,
		Local:    local,
	}, false)
}

func newWorkerTransactionID() (string, error) {
	nonce, err := workerproto.NewNonce()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce), nil
}

// applyPortMutation retries one transaction identity and reconciles lost
// responses against both the worker's transaction cache and its effective
// listener set. If neither can establish the outcome, the worker is stopped:
// an unknown inbound hole must never outlive a failed control operation.
func (w *netWorker) applyPortMutation(op, transaction string, request any, forward vnet.Forward, present bool) error {
	w.portMu.Lock()
	defer w.portMu.Unlock()

	var failures []error
	for attempt := 0; attempt < 2; attempt++ {
		var response networkworker.PortStatusResponse
		if err := w.client.Call(op, request, &response); err == nil {
			if response.Transaction == transaction {
				if conclusive, resultErr := portMutationResult(response); conclusive {
					return resultErr
				} else {
					failures = append(failures, resultErr)
				}
			} else {
				failures = append(failures, fmt.Errorf(
					"%s returned transaction %q, want %q", op, response.Transaction, transaction))
			}
		} else {
			failures = append(failures, fmt.Errorf("%s: %w", op, err))
		}

		status, err := w.readPortStatus(transaction)
		if err != nil {
			failures = append(failures, fmt.Errorf("port status: %w", err))
			continue
		}
		switch status.State {
		case networkworker.PortStateApplied, networkworker.PortStateRejected:
			_, resultErr := portMutationResult(status)
			return resultErr
		case networkworker.PortStateUnknown:
			// The request may have failed before dispatch. Replaying the exact
			// transaction is safe and gives it one chance to execute.
		default:
			failures = append(failures, fmt.Errorf("port status returned invalid state %q", status.State))
		}
	}

	forwards, err := w.Forwards()
	if err != nil {
		failures = append(failures, fmt.Errorf("port list reconciliation: %w", err))
		return w.stopAfterAmbiguousPort(errors.Join(failures...))
	}
	if portMutationEffective(forwards, forward, present) {
		return nil
	}
	// The effective state is still the pre-transaction state. Returning an
	// error is safe: PortManager leaves persistence untouched.
	return errors.Join(failures...)
}

func (w *netWorker) readPortStatus(transaction string) (networkworker.PortStatusResponse, error) {
	var status networkworker.PortStatusResponse
	err := w.client.Call(networkworker.OpPortStatus,
		networkworker.PortStatusRequest{Transaction: transaction}, &status)
	if err == nil && status.Transaction != transaction {
		err = fmt.Errorf("port status returned transaction %q, want %q", status.Transaction, transaction)
	}
	return status, err
}

func portMutationResult(response networkworker.PortStatusResponse) (bool, error) {
	switch response.State {
	case networkworker.PortStateApplied:
		return true, nil
	case networkworker.PortStateRejected:
		if response.Error == "" {
			return true, fmt.Errorf("port mutation rejected")
		}
		return true, errors.New(response.Error)
	default:
		return false, fmt.Errorf("port mutation returned invalid state %q", response.State)
	}
}

func portMutationEffective(forwards []vnet.Forward, target vnet.Forward, present bool) bool {
	for _, forward := range forwards {
		proto := forward.Protocol
		if proto == "" {
			proto = "tcp"
		}
		if proto != target.Protocol || forward.Local != target.Local {
			continue
		}
		if !present {
			return false
		}
		if forward.Remote == target.Remote {
			return true
		}
	}
	return !present
}

func (w *netWorker) stopAfterAmbiguousPort(cause error) error {
	stopErr := w.Close()
	return errors.Join(cause, fmt.Errorf("port forwarding state ambiguous; network worker stopped"), stopErr)
}

func (w *netWorker) Forwards() ([]vnet.Forward, error) {
	var out []vnet.Forward
	err := w.client.Call(networkworker.OpPortList, nil, &out)
	return out, err
}

// TrafficSnapshot fetches the worker's current per-boot counters.
func (w *netWorker) TrafficSnapshot() (netpol.TrafficSnapshot, error) {
	var out netpol.TrafficSnapshot
	err := w.client.Call(networkworker.OpTrafficSnapshot, nil, &out)
	return out, err
}

func (w *netWorker) trafficSnapshotContext(ctx context.Context) (netpol.TrafficSnapshot, error) {
	var out netpol.TrafficSnapshot
	err := w.client.CallContext(ctx, networkworker.OpTrafficSnapshot, nil, &out)
	return out, err
}

// Close asks the worker for its final traffic snapshot and graceful shutdown,
// then closes both channels and reaps the process,
// escalating to a kill after a bounded wait. It is idempotent: failure
// handling and deferred sandbox cleanup may call it concurrently.
func (w *netWorker) Close() error {
	w.closeOnce.Do(func() {
		var shutdownErr error
		w.lifecycle.BeginStop()
		w.stopTrafficSync()
		if w.client != nil {
			var response networkworker.ShutdownResponse
			if err := w.client.CallWithTimeout(networkworker.OpShutdown, nil, &response, 5*time.Second); err != nil {
				shutdownErr = fmt.Errorf("network worker shutdown: %w", err)
			} else {
				w.mergeFinalTraffic(response.Traffic)
			}
			_ = w.client.Close()
		}
		if w.data != nil {
			_ = w.data.Close()
		}
		if w.kill != nil {
			w.closeErr = errors.Join(shutdownErr, w.lifecycle.WaitExit(5*time.Second, w.kill))
		} else {
			// In-process tests have no process to reap. Preserve a published
			// terminal error without waiting forever on a live helper.
			select {
			case <-w.Done():
				w.closeErr = errors.Join(shutdownErr, w.Err())
			default:
				w.closeErr = shutdownErr
			}
		}
	})
	return w.closeErr
}

// netWorkerTrafficDebug mirrors GANTRY_DEBUG_NET into the bootstrap config.
func netWorkerTrafficDebug() bool { return os.Getenv("GANTRY_DEBUG_NET") != "" }
