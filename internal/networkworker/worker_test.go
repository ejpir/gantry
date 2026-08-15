package networkworker

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/workerproto"
)

func TestPumpFramesReportsReadFailure(t *testing.T) {
	dst, dstPeer := net.Pipe()
	src, srcPeer := net.Pipe()
	defer func() { _ = dstPeer.Close() }()
	defer func() { _ = srcPeer.Close() }()

	done := make(chan error, 1)
	go func() { done <- pumpFrames(dst, src, func([]byte) bool { return true }) }()
	if err := srcPeer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) || !strings.Contains(err.Error(), "read frame") {
			t.Fatalf("pump error = %v, want read-frame EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pump did not report source closure")
	}
}

func TestPumpFramesReportsMalformedFrame(t *testing.T) {
	dst, dstPeer := net.Pipe()
	src, srcPeer := net.Pipe()
	defer func() { _ = dstPeer.Close() }()
	defer func() { _ = srcPeer.Close() }()

	done := make(chan error, 1)
	go func() { done <- pumpFrames(dst, src, func([]byte) bool { return true }) }()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], workerproto.MaxFrame+1)
	if _, err := srcPeer.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "frame length") {
			t.Fatalf("pump error = %v, want frame-length failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pump did not reject malformed frame")
	}
}

func TestPumpFramesReportsWriteFailure(t *testing.T) {
	dst, dstPeer := net.Pipe()
	src, srcPeer := net.Pipe()
	defer func() { _ = srcPeer.Close() }()
	if err := dstPeer.Close(); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- pumpFrames(dst, src, func([]byte) bool { return true }) }()
	if err := workerproto.WriteFrame(srcPeer, make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "write frame") {
			t.Fatalf("pump error = %v, want write-frame failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pump did not report destination closure")
	}
}

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
