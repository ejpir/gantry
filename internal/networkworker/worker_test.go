package networkworker

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/vnet"
	"github.com/ejpir/gantry/internal/workerproto"
)

type workerPortStackStub struct {
	mu               sync.Mutex
	forwards         []vnet.Forward
	publishStarted   chan struct{}
	releasePublish   chan struct{}
	publishStartOnce sync.Once
}

func (s *workerPortStackStub) Publish(proto, local, remote string) error {
	if s.publishStarted != nil {
		s.publishStartOnce.Do(func() { close(s.publishStarted) })
	}
	if s.releasePublish != nil {
		<-s.releasePublish
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forwards = append(s.forwards, vnet.Forward{Local: local, Remote: remote, Protocol: proto})
	return nil
}

func (s *workerPortStackStub) Unpublish(proto, local string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, forward := range s.forwards {
		if forward.Protocol == proto && forward.Local == local {
			s.forwards = append(s.forwards[:i], s.forwards[i+1:]...)
			break
		}
	}
	return nil
}

func (s *workerPortStackStub) Forwards() ([]vnet.Forward, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]vnet.Forward(nil), s.forwards...), nil
}

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
	return &state{stack: &workerPortStackStub{}, policy: live, currentDigest: sha256.Sum256(raw)}, live
}

func TestStaticUDPForwardsRequireGatewayReplyPolicy(t *testing.T) {
	denied := netpol.DefaultPolicy()
	udp := map[string]string{"udp:127.0.0.1:18081": "192.168.127.2:18081"}
	if err := validateStaticUDPPortPolicy(denied, udp); err == nil {
		t.Fatal("default local-network wall accepted a static worker UDP forward")
	} else if !strings.Contains(err.Error(), "gateway reply port") {
		t.Fatalf("static worker UDP policy error = %v", err)
	}
	if err := validateStaticUDPPortPolicy(denied, map[string]string{
		"127.0.0.1:18080": "192.168.127.2:18080",
	}); err != nil {
		t.Fatalf("TCP static forward was rejected: %v", err)
	}
	allowed := netpol.DefaultPolicy()
	allowed.AllowLocal = true
	if err := validateStaticUDPPortPolicy(allowed, udp); err != nil {
		t.Fatalf("allow-local policy rejected static worker UDP forward: %v", err)
	}
}

func TestRunRejectsStaticUDPBeforeOpeningListener(t *testing.T) {
	const local = "127.0.0.1:48081"

	controlSupervisor, controlWorker := net.Pipe()
	dataSupervisor, dataWorker := net.Pipe()
	defer func() { _ = controlSupervisor.Close() }()
	defer func() { _ = dataSupervisor.Close() }()
	done := make(chan error, 1)
	go func() { done <- Run(controlWorker, dataWorker) }()

	nonce, err := workerproto.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		GuestMAC:    "5a:94:ef:e4:0c:ee",
		Forwards:    map[string]string{"udp:" + local: "192.168.127.2:18081"},
		Policy:      json.RawMessage(`{"default":"allow"}`),
		Confinement: "off",
	}
	if err := workerproto.SendHandshake(controlSupervisor, workerproto.RoleNet, nonce, cfg); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "gateway reply port") {
			t.Fatalf("worker static UDP bootstrap error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not reject the static UDP forward")
	}
}

func TestLiveUDPForwardRequiresGatewayReplyPolicy(t *testing.T) {
	workerState := &state{policy: netpol.DefaultPolicy()}
	result, err := workerState.publishPort(testRequest(t, PortPublishRequest{
		Transaction: "udp-policy", Proto: "udp",
		Local: "127.0.0.1:18081", Remote: "192.168.127.2:18081",
	}))
	if err != nil {
		t.Fatal(err)
	}
	response, ok := result.(PortStatusResponse)
	if !ok {
		t.Fatalf("UDP publish response type = %T", result)
	}
	if response.State != PortStateRejected || !strings.Contains(response.Error, "gateway reply port") {
		t.Fatalf("UDP publish response = %+v", response)
	}
	if replay, err := workerState.publishPort(testRequest(t, PortPublishRequest{
		Transaction: "udp-policy", Proto: "udp",
		Local: "127.0.0.1:18081", Remote: "192.168.127.2:18081",
	})); err != nil || replay != response {
		t.Fatalf("replayed UDP rejection = %+v, err=%v", replay, err)
	}
}

func TestPolicyCommitSerializesWithUDPPublish(t *testing.T) {
	s, live := testPolicyState(t)
	stack := &workerPortStackStub{
		publishStarted: make(chan struct{}),
		releasePublish: make(chan struct{}),
	}
	s.stack = stack

	type callResult struct {
		value any
		err   error
	}
	publishDone := make(chan callResult, 1)
	go func() {
		value, err := s.publishPort(testRequest(t, PortPublishRequest{
			Transaction: "udp-before-policy", Proto: "udp",
			Local: "127.0.0.1:18081", Remote: vnet.GuestIP + ":18081",
		}))
		publishDone <- callResult{value: value, err: err}
	}()
	select {
	case <-stack.publishStarted:
	case <-time.After(time.Second):
		t.Fatal("UDP publish did not reach the worker stack")
	}

	if _, err := s.preparePolicy(testRequest(t, PolicyPrepareRequest{
		Generation: 1, Transaction: "deny-with-udp", Policy: json.RawMessage(`{"default":"deny"}`),
	})); err != nil {
		t.Fatal(err)
	}
	commit := testRequest(t, PolicyGenerationRequest{Generation: 1, Transaction: "deny-with-udp"})
	commitDone := make(chan callResult, 1)
	go func() {
		value, err := s.commitPolicy(commit)
		commitDone <- callResult{value: value, err: err}
	}()
	select {
	case result := <-commitDone:
		close(stack.releasePublish)
		<-publishDone
		t.Fatalf("policy commit overtook an in-flight UDP publish: value=%+v err=%v", result.value, result.err)
	case <-time.After(50 * time.Millisecond):
	}

	close(stack.releasePublish)
	published := <-publishDone
	if published.err != nil {
		t.Fatal(published.err)
	}
	response, ok := published.value.(PortStatusResponse)
	if !ok || response.State != PortStateApplied {
		t.Fatalf("UDP publish response = %+v", published.value)
	}
	committed := <-commitDone
	if committed.err == nil || !strings.Contains(committed.err.Error(), "gateway reply port") {
		t.Fatalf("policy commit with active UDP forward: value=%+v err=%v", committed.value, committed.err)
	}
	if err := netpol.ValidateUDPPortPublishing(live); err != nil {
		t.Fatalf("rejected commit changed the live policy: %v", err)
	}

	if _, err := s.unpublishPort(testRequest(t, PortUnpublishRequest{
		Transaction: "remove-udp", Proto: "udp", Local: "127.0.0.1:18081",
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := s.commitPolicy(commit); err != nil {
		t.Fatalf("policy commit after UDP unpublish: %v", err)
	}
	if err := netpol.ValidateUDPPortPublishing(live); err == nil {
		t.Fatal("committed deny policy still permits UDP gateway replies")
	}
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

func TestHostLoopbackUnavailableRejectsPolicyAndPublish(t *testing.T) {
	live, err := netpol.Parse([]byte(`{"default":"deny"}`))
	if err != nil {
		t.Fatal(err)
	}
	s := &state{policy: live, hostLoopbackUnavailable: true}
	_, err = s.preparePolicy(testRequest(t, PolicyPrepareRequest{
		Generation: 1, Transaction: "loopback", Policy: json.RawMessage(
			`{"default":"deny","rules":[{"action":"allow","cidr":"127.0.0.1/32"}]}`),
	}))
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("loopback policy error = %v", err)
	}
	_, err = s.publishPort(testRequest(t, PortPublishRequest{
		Transaction: "publish", Proto: "tcp", Local: "127.0.0.1:8080", Remote: "192.168.127.2:80",
	}))
	if err == nil || !strings.Contains(err.Error(), "port publishing") {
		t.Fatalf("publish error = %v", err)
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
