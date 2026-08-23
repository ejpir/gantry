package networkworker

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/packetcapture"
	"github.com/ejpir/gantry/internal/vnet"
	"github.com/ejpir/gantry/internal/workerproto"
)

// state holds the worker's mutable services. Policy and port transitions use
// independent locks; traffic recording is independently safe.
type state struct {
	stack         *vnet.Stack
	policy        *netpol.Policy // stable holder attached to the pumps
	currentTxn    string
	currentDigest [sha256.Size]byte
	pending       *netpol.Policy // prepared, awaiting commit
	pendingTxn    string
	pendingDigest [sha256.Size]byte
	gen           uint64
	pendGen       uint64
	traffic       *netpol.TrafficRecorder
	portTxns      map[string]portTransaction
	portTxnOrder  [maxPortTransactions]string
	portTxnNext   int
	// shutdownRequested distinguishes a supervisor's graceful stop from
	// a torn data link when both race the serve loop below.
	shutdownRequested       atomic.Bool
	hostLoopbackUnavailable bool
	policyMu                sync.Mutex
	portMu                  sync.Mutex
}

const (
	maxPortTransactions = 64
	maxPortAddressBytes = 256
)

type portMutation struct {
	operation string
	proto     string
	local     string
	remote    string
}

type portTransaction struct {
	mutation portMutation
	response PortStatusResponse
}

func (s *state) preparePolicy(req workerproto.Request) (any, error) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	var body PolicyPrepareRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		return nil, err
	}
	if body.Transaction == "" || len(body.Transaction) > 128 {
		return nil, fmt.Errorf("invalid policy transaction ID")
	}
	digest := sha256.Sum256(body.Policy)
	// A retried request whose response was lost is a no-op only when both
	// its identity and content match. Reusing an ID for different policy
	// bytes is a protocol error, never an accidental commit.
	if body.Generation == s.gen && body.Transaction == s.currentTxn {
		if digest != s.currentDigest {
			return nil, fmt.Errorf("policy transaction %q reused with different content", body.Transaction)
		}
		return s.statusLocked(body.Transaction), nil
	}
	if s.pending != nil && body.Generation == s.pendGen && body.Transaction == s.pendingTxn {
		if digest != s.pendingDigest {
			return nil, fmt.Errorf("policy transaction %q reused with different content", body.Transaction)
		}
		return s.statusLocked(body.Transaction), nil
	}
	if s.pending != nil {
		return nil, fmt.Errorf("policy transaction %q generation %d already prepared", s.pendingTxn, s.pendGen)
	}
	if body.Generation != s.gen+1 {
		return nil, fmt.Errorf("policy generation %d out of order (current %d)", body.Generation, s.gen)
	}
	next, err := netpol.Parse(body.Policy)
	if err != nil {
		return nil, err
	}
	if s.hostLoopbackUnavailable && next.MayAllowLoopback() {
		return nil, fmt.Errorf("policy permits host loopback, which is unavailable to the confined Windows network worker")
	}
	s.pending = next
	s.pendGen = body.Generation
	s.pendingTxn = body.Transaction
	s.pendingDigest = digest
	return s.statusLocked(body.Transaction), nil
}

func (s *state) commitPolicy(req workerproto.Request) (any, error) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	var body PolicyGenerationRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		return nil, err
	}
	if body.Transaction == "" || len(body.Transaction) > 128 {
		return nil, fmt.Errorf("invalid policy transaction ID")
	}
	if body.Generation == s.gen && body.Transaction == s.currentTxn {
		return s.statusLocked(body.Transaction), nil // idempotent replay
	}
	if s.pending == nil || body.Generation != s.pendGen || body.Transaction != s.pendingTxn {
		return nil, fmt.Errorf("no prepared policy transaction %q generation %d", body.Transaction, body.Generation)
	}
	if err := s.policy.Replace(s.pending); err != nil {
		return nil, err
	}
	s.currentTxn = s.pendingTxn
	s.currentDigest = s.pendingDigest
	s.pending = nil
	s.pendingTxn = ""
	s.pendingDigest = [sha256.Size]byte{}
	s.gen = body.Generation
	s.pendGen = 0
	return s.statusLocked(body.Transaction), nil
}

// abortPolicy drops a prepared transaction without touching the active
// generation. It is idempotent for an already-committed or absent transaction;
// the supervisor uses status readback to distinguish those outcomes.
func (s *state) abortPolicy(req workerproto.Request) (any, error) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	var body PolicyGenerationRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		return nil, err
	}
	if s.pending != nil && body.Generation == s.pendGen && body.Transaction == s.pendingTxn {
		s.pending = nil
		s.pendingTxn = ""
		s.pendingDigest = [sha256.Size]byte{}
		s.pendGen = 0
		return s.statusLocked(body.Transaction), nil
	}
	if s.pending != nil {
		return nil, fmt.Errorf("different policy transaction %q generation %d is prepared", s.pendingTxn, s.pendGen)
	}
	return s.statusLocked(body.Transaction), nil
}

func (s *state) policyStatus(req workerproto.Request) (any, error) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	var body PolicyGenerationRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		return nil, err
	}
	return s.statusLocked(body.Transaction), nil
}

func (s *state) statusLocked(transaction string) PolicyStatusResponse {
	status := PolicyStatusResponse{
		State:              PolicyStateUnknown,
		Generation:         s.gen,
		Transaction:        s.currentTxn,
		PendingGeneration:  s.pendGen,
		PendingTransaction: s.pendingTxn,
	}
	switch {
	case transaction == "":
		status.State = PolicyStateCurrent
	case transaction == s.currentTxn && s.currentTxn != "":
		status.State = PolicyStateCommitted
	case transaction == s.pendingTxn && s.pendingTxn != "":
		status.State = PolicyStatePrepared
	}
	return status
}

func (s *state) publishPort(req workerproto.Request) (any, error) {
	if s.hostLoopbackUnavailable {
		return nil, fmt.Errorf("port publishing is unavailable to the confined Windows network worker")
	}
	var body PortPublishRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		return nil, err
	}
	mutation := portMutation{
		operation: OpPortPublish,
		proto:     body.Proto,
		local:     body.Local,
		remote:    body.Remote,
	}
	return s.applyPortMutation(body.Transaction, mutation, func() error {
		return s.stack.Publish(body.Proto, body.Local, body.Remote)
	})
}

func (s *state) unpublishPort(req workerproto.Request) (any, error) {
	var body PortUnpublishRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		return nil, err
	}
	mutation := portMutation{
		operation: OpPortUnpublish,
		proto:     body.Proto,
		local:     body.Local,
	}
	return s.applyPortMutation(body.Transaction, mutation, func() error {
		return s.stack.Unpublish(body.Proto, body.Local)
	})
}

func (s *state) portStatus(req workerproto.Request) (any, error) {
	var body PortStatusRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		return nil, err
	}
	if err := validatePortTransaction(body.Transaction); err != nil {
		return nil, err
	}
	s.portMu.Lock()
	defer s.portMu.Unlock()
	if transaction, ok := s.portTxns[body.Transaction]; ok {
		return transaction.response, nil
	}
	return PortStatusResponse{
		Transaction: body.Transaction,
		State:       PortStateUnknown,
	}, nil
}

func (s *state) applyPortMutation(transaction string, mutation portMutation, apply func() error) (PortStatusResponse, error) {
	if err := validatePortTransaction(transaction); err != nil {
		return PortStatusResponse{}, err
	}
	if mutation.proto != "tcp" && mutation.proto != "udp" {
		return PortStatusResponse{}, fmt.Errorf("unsupported port protocol %q", mutation.proto)
	}
	if mutation.local == "" || len(mutation.local) > maxPortAddressBytes ||
		len(mutation.remote) > maxPortAddressBytes ||
		(mutation.operation == OpPortPublish && mutation.remote == "") {
		return PortStatusResponse{}, fmt.Errorf("invalid port forwarding address")
	}

	s.portMu.Lock()
	defer s.portMu.Unlock()
	if previous, ok := s.portTxns[transaction]; ok {
		if previous.mutation != mutation {
			return PortStatusResponse{}, fmt.Errorf("port transaction %q reused for a different mutation", transaction)
		}
		return previous.response, nil
	}

	response := PortStatusResponse{Transaction: transaction, State: PortStateApplied}
	if err := apply(); err != nil {
		response.State = PortStateRejected
		response.Error = err.Error()
	}
	s.rememberPortTransaction(transaction, portTransaction{
		mutation: mutation,
		response: response,
	})
	return response, nil
}

func (s *state) rememberPortTransaction(id string, transaction portTransaction) {
	if s.portTxns == nil {
		s.portTxns = make(map[string]portTransaction, maxPortTransactions)
	}
	if len(s.portTxns) == maxPortTransactions {
		delete(s.portTxns, s.portTxnOrder[s.portTxnNext])
	}
	s.portTxns[id] = transaction
	s.portTxnOrder[s.portTxnNext] = id
	s.portTxnNext = (s.portTxnNext + 1) % maxPortTransactions
}

func validatePortTransaction(transaction string) error {
	if transaction == "" || len(transaction) > 128 {
		return fmt.Errorf("invalid port transaction ID")
	}
	return nil
}

func (s *state) listPorts(workerproto.Request) (any, error) {
	return s.stack.Forwards()
}

func (s *state) trafficSnapshot(workerproto.Request) (any, error) {
	return s.traffic.Snapshot(), nil
}

func (s *state) capture(request workerproto.Request) (any, error) {
	var body packetcapture.Request
	if err := workerproto.DecodeBody(request, &body); err != nil {
		return nil, fmt.Errorf("capture.read: %w", err)
	}
	return s.traffic.Capture(body)
}

func (s *state) shutdown(workerproto.Request) (any, error) {
	s.shutdownRequested.Store(true)
	response := ShutdownResponse{}
	if s.traffic != nil {
		snapshot := s.traffic.Snapshot()
		response.Traffic = &snapshot
	}
	return response, workerproto.ErrShutdown
}
