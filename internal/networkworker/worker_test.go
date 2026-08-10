package networkworker

import (
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/workerproto"
)

func testRequest(t *testing.T, body any) workerproto.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return workerproto.Request{Body: raw}
}

func testPolicyState(t *testing.T) (*state, *netpol.Policy) {
	t.Helper()
	live, err := netpol.Parse([]byte(`{"default":"allow","allowLocal":true}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := netpol.Marshal(live)
	if err != nil {
		t.Fatal(err)
	}
	return &state{policy: live, currentDigest: sha256.Sum256(raw)}, live
}

func TestPolicyTransactionsOrderingReplayAndAbort(t *testing.T) {
	s, live := testPolicyState(t)
	deny := json.RawMessage(`{"default":"deny"}`)
	allow := json.RawMessage(`{"default":"allow","allowLocal":true}`)

	if _, err := s.preparePolicy(testRequest(t, PolicyPrepareRequest{
		Generation: 2, Transaction: "out-of-order", Policy: deny,
	})); err == nil {
		t.Fatal("out-of-order prepare accepted")
	}

	prepare := PolicyPrepareRequest{Generation: 1, Transaction: "txn-1", Policy: deny}
	if _, err := s.preparePolicy(testRequest(t, prepare)); err != nil {
		t.Fatal(err)
	}
	if status := s.statusLocked("txn-1"); status.State != PolicyStatePrepared ||
		status.PendingGeneration != 1 || status.PendingTransaction != "txn-1" {
		t.Fatalf("prepared status = %+v", status)
	}
	if _, err := s.preparePolicy(testRequest(t, prepare)); err != nil {
		t.Fatalf("idempotent prepare: %v", err)
	}
	prepare.Policy = allow
	if _, err := s.preparePolicy(testRequest(t, prepare)); err == nil {
		t.Fatal("transaction ID reused with different policy")
	}

	if _, err := s.commitPolicy(testRequest(t, PolicyGenerationRequest{
		Generation: 1, Transaction: "wrong",
	})); err == nil {
		t.Fatal("commit accepted wrong transaction")
	}
	commit := PolicyGenerationRequest{Generation: 1, Transaction: "txn-1"}
	if _, err := s.commitPolicy(testRequest(t, commit)); err != nil {
		t.Fatal(err)
	}
	if live.Allows([4]byte{8, 8, 8, 8}, 6, 443) {
		t.Fatal("committed deny policy was not applied")
	}
	if status := s.statusLocked("txn-1"); status.State != PolicyStateCommitted || status.Generation != 1 {
		t.Fatalf("committed status = %+v", status)
	}
	if _, err := s.commitPolicy(testRequest(t, commit)); err != nil {
		t.Fatalf("idempotent commit: %v", err)
	}

	prepare = PolicyPrepareRequest{Generation: 2, Transaction: "txn-2", Policy: allow}
	if _, err := s.preparePolicy(testRequest(t, prepare)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.abortPolicy(testRequest(t, PolicyGenerationRequest{
		Generation: 2, Transaction: "txn-2",
	})); err != nil {
		t.Fatal(err)
	}
	if status := s.statusLocked("txn-2"); status.State != PolicyStateUnknown ||
		status.Generation != 1 || status.PendingTransaction != "" {
		t.Fatalf("aborted status = %+v", status)
	}
}

func TestPolicyTransactionIDValidation(t *testing.T) {
	s, _ := testPolicyState(t)
	for _, txn := range []string{"", string(make([]byte, 129))} {
		if _, err := s.preparePolicy(testRequest(t, PolicyPrepareRequest{
			Generation: 1, Transaction: txn, Policy: json.RawMessage(`{"default":"deny"}`),
		})); err == nil {
			t.Fatalf("prepare accepted transaction length %d", len(txn))
		}
	}
}
