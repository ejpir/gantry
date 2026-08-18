//go:build linux || darwin

package networker

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/networkworker"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/worker"
	"github.com/ejpir/gantry/internal/sandbox/worker/workertest"
	"github.com/ejpir/gantry/internal/vnet"
	"github.com/ejpir/gantry/internal/workerproto"
)

// testMAC mirrors the production guest MAC (runconf guestNetMAC is
// unexported package state; the worker only needs SOME fixed address).
var testWorkerMAC = "5a:94:ef:e4:0c:ee"

type closeCountingConn struct {
	net.Conn
	count  atomic.Int32
	closed chan struct{}
	once   sync.Once
}

func testWorkerNonce(t *testing.T) []byte {
	t.Helper()
	nonce, err := workerproto.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	return nonce
}

func (c *closeCountingConn) Close() error {
	c.count.Add(1)
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// workerTestFrame builds a minimal Ethernet+IPv4(+TCP/UDP) frame from the
// guest to dstIP:dstPort — the shape netpol.MatchTX parses.
func workerTestFrame(t *testing.T, dstIP string, proto uint8, dport uint16) []byte {
	t.Helper()
	dst := net.ParseIP(dstIP).To4()
	src := net.ParseIP("192.168.127.2").To4()
	var l4 []byte
	switch proto {
	case 17: // udp
		l4 = make([]byte, 8)
		binary.BigEndian.PutUint16(l4[0:2], 12345)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		binary.BigEndian.PutUint16(l4[4:6], 8)
	case 6: // tcp
		l4 = make([]byte, 20)
		binary.BigEndian.PutUint16(l4[0:2], 12345)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		l4[12] = 5 << 4
		l4[13] = 0x02 // SYN
	default: // icmp
		l4 = make([]byte, 8)
	}
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(l4)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	frame := make([]byte, 0, 14+len(ip)+len(l4))
	gw, _ := net.ParseMAC("5a:94:ef:e4:0c:dd")
	guest, _ := net.ParseMAC(testWorkerMAC)
	frame = append(frame, gw...)
	frame = append(frame, guest...)
	frame = append(frame, 0x08, 0x00) // IPv4
	frame = append(frame, ip...)
	frame = append(frame, l4...)
	return frame
}

// startInProcessWorker drives networkworker.Run on net.Pipe channels and
// performs the supervisor-side handshake + nonce, returning the ready
// backend. The worker goroutine exits when the backend is closed.
// expectDeath tolerates an error exit in cleanup (the malformed-frame
// test kills the worker on purpose).
func startInProcessWorker(t *testing.T, cfg networkworker.Config, expectDeath ...bool) (*Worker, net.Conn) {
	t.Helper()
	ctrlSup, ctrlWrk := net.Pipe()
	dataSup, dataWrk := net.Pipe()
	workerErr := make(chan error, 1)
	go func() { workerErr <- networkworker.Run(ctrlWrk, dataWrk) }()

	nonce := testWorkerNonce(t)
	if err := workerproto.SendHandshake(ctrlSup, workerproto.RoleNet, nonce, cfg); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.WriteNonce(dataSup, nonce); err != nil {
		t.Fatal(err)
	}
	var ack workerproto.Response
	_ = ctrlSup.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := workerproto.ReadMessage(ctrlSup, &ack); err != nil {
		t.Fatalf("worker ack: %v", err)
	}
	_ = ctrlSup.SetReadDeadline(time.Time{})
	if !ack.OK {
		t.Fatal("worker bootstrap refused")
	}
	w := Attach(ctrlSup, dataSup)
	tolerate := len(expectDeath) > 0 && expectDeath[0]
	t.Cleanup(func() {
		if err := w.Close(); err != nil && !tolerate {
			t.Errorf("worker close: %v", err)
		}
		select {
		case err := <-workerErr:
			if err != nil && !tolerate {
				t.Errorf("worker exited with error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("worker did not exit after shutdown")
		}
	})
	return w, dataSup
}

func testWorkerConfig(t *testing.T, policyJSON string) networkworker.Config {
	t.Helper()
	return networkworker.Config{
		GuestMAC:    testWorkerMAC,
		Policy:      json.RawMessage(policyJSON),
		Confinement: "off",
	}
}

func TestNetWorkerLifecycleAndPorts(t *testing.T) {
	w, _ := startInProcessWorker(t, testWorkerConfig(t, `{"default":"allow"}`))

	// port publish → list → unpublish round-trip over RPC
	if err := w.Publish("tcp", "127.0.0.1:18081", "192.168.127.2:8081"); err != nil {
		t.Fatal(err)
	}
	fw, err := w.Forwards()
	if err != nil {
		t.Fatal(err)
	}
	if len(fw) != 1 || fw[0].Local != "127.0.0.1:18081" {
		t.Fatalf("forwards: %+v", fw)
	}
	if err := w.Unpublish("tcp", "127.0.0.1:18081"); err != nil {
		t.Fatal(err)
	}
	fw, err = w.Forwards()
	if err != nil || len(fw) != 0 {
		t.Fatalf("after unpublish: %+v err=%v", fw, err)
	}

	// traffic snapshot RPC is live and empty
	snap, err := w.TrafficSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.TXPackets != 0 || snap.DroppedPackets != 0 {
		t.Fatalf("unexpected counters: %+v", snap)
	}
}

func TestNetWorkerPortTransactionsAreIdempotent(t *testing.T) {
	w, _ := startInProcessWorker(t, testWorkerConfig(t, `{"default":"allow"}`))
	port, err := config.FreePortForProto("tcp", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	request := networkworker.PortPublishRequest{
		Transaction: "publish-once",
		Proto:       "tcp",
		Local:       fmt.Sprintf("127.0.0.1:%d", port),
		Remote:      "192.168.127.2:8080",
	}
	for i := 0; i < 2; i++ {
		var response networkworker.PortStatusResponse
		if err := w.client.Call(networkworker.OpPortPublish, request, &response); err != nil {
			t.Fatalf("publish replay %d: %v", i+1, err)
		}
		if response.Transaction != request.Transaction || response.State != networkworker.PortStateApplied {
			t.Fatalf("publish replay %d response = %+v", i+1, response)
		}
	}
	forwards, err := w.Forwards()
	if err != nil || len(forwards) != 1 {
		t.Fatalf("idempotent publish forwards = %+v, err=%v", forwards, err)
	}

	reused := request
	reused.Remote = "192.168.127.2:9090"
	if err := w.client.Call(networkworker.OpPortPublish, reused, nil); err == nil {
		t.Fatal("transaction ID reuse with different content succeeded")
	}

	unpublish := networkworker.PortUnpublishRequest{
		Transaction: "unpublish-once",
		Proto:       request.Proto,
		Local:       request.Local,
	}
	for i := 0; i < 2; i++ {
		var response networkworker.PortStatusResponse
		if err := w.client.Call(networkworker.OpPortUnpublish, unpublish, &response); err != nil {
			t.Fatalf("unpublish replay %d: %v", i+1, err)
		}
		if response.State != networkworker.PortStateApplied {
			t.Fatalf("unpublish replay %d response = %+v", i+1, response)
		}
	}
	if forwards, err := w.Forwards(); err != nil || len(forwards) != 0 {
		t.Fatalf("idempotent unpublish forwards = %+v, err=%v", forwards, err)
	}
}

// TestNetWorkerDoneConsumptionDoesNotBlockClose is the failure-teardown
// regression. Done used to carry one buffered error value: the daemon consumed
// it in its fatal-worker select, then deferred Close waited forever for a
// second value after trying to kill an already-reaped process. A closed channel
// must broadcast death independently of Err retrieval.
func TestNetWorkerDoneConsumptionDoesNotBlockClose(t *testing.T) {
	want := errors.New("worker failed")
	diagnosticPath := filepath.Join(t.TempDir(), "worker-net.log")
	if err := os.WriteFile(diagnosticPath, []byte("net-worker: exact pump failure\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var kills atomic.Int32
	w := &Worker{
		lifecycle:      worker.NewLifecycle(),
		diagnosticPath: diagnosticPath,
		kill: func() error {
			kills.Add(1)
			return nil
		},
	}
	w.setDead(want)
	if err := w.Err(); err == nil || !strings.Contains(err.Error(), "exact pump failure") {
		t.Fatalf("worker error omitted diagnostic tail: %v", err)
	}

	// Model the daemon selecting the death notification before deferred
	// cleanup calls Close.
	<-w.Done()
	select {
	case <-w.Done(): // a second observer must see the same terminal event
	default:
		t.Fatal("Done is not a closed broadcast channel")
	}

	closed := make(chan error, 1)
	go func() { closed <- w.Close() }()
	select {
	case err := <-closed:
		if !errors.Is(err, want) {
			t.Fatalf("Close error = %v, want %v", err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked after Done had already been consumed")
	}
	if got := kills.Load(); got != 0 {
		t.Fatalf("Close killed an already-reaped worker %d time(s)", got)
	}
}

func TestNetWorkerCloseReportsShutdownRPCFailure(t *testing.T) {
	supervisor, peer := net.Pipe()
	client := workerproto.NewClient(supervisor)
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	nw := &Worker{client: client, lifecycle: worker.NewLifecycle()}

	err := nw.Close()
	if err == nil || !strings.Contains(err.Error(), "network worker shutdown") {
		t.Fatalf("Close error = %v, want shutdown RPC failure", err)
	}
}

// TestNetWorkerCloseConcurrentIdempotent exercises the teardown races that can
// stack in production (fatal worker notification, Network.Close, and deferred
// daemon cleanup). Exactly one caller owns channel teardown; every caller sees
// the same stored exit error.
func TestNetWorkerCloseConcurrentIdempotent(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	data := &closeCountingConn{Conn: a, closed: make(chan struct{})}
	want := errors.New("worker exited")
	var kills atomic.Int32
	w := &Worker{
		data:      data,
		lifecycle: worker.NewLifecycle(),
		kill: func() error {
			kills.Add(1)
			return nil
		},
	}

	const callers = 32
	results := make(chan error, callers)
	observed := make(chan error, callers)
	for i := 0; i < callers; i++ {
		go func() {
			<-w.Done()
			observed <- w.Err()
		}()
		go func() { results <- w.Close() }()
	}

	select {
	case <-data.closed:
	case <-time.After(time.Second):
		t.Fatal("no Close caller began channel teardown")
	}
	w.setDead(want)
	// A duplicate terminal publication must neither panic nor replace the
	// authoritative first result.
	w.setDead(errors.New("late duplicate result"))

	for i := 0; i < callers; i++ {
		if err := <-results; !errors.Is(err, want) {
			t.Errorf("Close caller %d error = %v, want %v", i, err, want)
		}
		if err := <-observed; !errors.Is(err, want) {
			t.Errorf("Done observer %d error = %v, want %v", i, err, want)
		}
	}
	if got := data.count.Load(); got != 1 {
		t.Fatalf("data channel closed %d times, want once", got)
	}
	if got := kills.Load(); got != 0 {
		t.Fatalf("already-dead worker killed %d times", got)
	}
}

func TestNetWorkerPolicyEnforcedAcrossChannel(t *testing.T) {
	w, data := startInProcessWorker(t, testWorkerConfig(t, `{
		"default": "deny",
		"rules": [{"action":"allow","cidr":"203.0.113.0/24","proto":"tcp","ports":"443"}]
	}`))

	// allowed destination: crosses the data channel into the netstack
	if err := workerproto.WriteFrame(data, workerTestFrame(t, "203.0.113.7", 6, 443)); err != nil {
		t.Fatal(err)
	}
	// denied destination: dropped at the worker, counted
	if err := workerproto.WriteFrame(data, workerTestFrame(t, "198.51.100.9", 6, 443)); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		snap, err := w.TrafficSnapshot()
		if err != nil {
			t.Fatal(err)
		}
		// every guest frame counts as TX; denied ones ALSO count dropped
		if snap.TXPackets == 2 && snap.DroppedPackets == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("counters: %+v", snap)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Live replacement across the control channel: deny-all becomes
	// allow-all, and the previously dropped destination now flows.
	allow, err := netpol.Parse([]byte(`{"default":"allow"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetPolicy(allow); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.WriteFrame(data, workerTestFrame(t, "198.51.100.9", 6, 443)); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		snap, err := w.TrafficSnapshot()
		if err != nil {
			t.Fatal(err)
		}
		if snap.TXPackets == 3 && snap.DroppedPackets == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after replace: %+v", snap)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNetWorkerTrafficPersistsAcrossWorkerEpochsAndFinalSnapshots(t *testing.T) {
	path := filepath.Join(t.TempDir(), netpol.TrafficFileName)
	supervisor := netpol.NewTrafficRecorder(path)

	for boot := 0; boot < 2; boot++ {
		w, data := startInProcessWorker(t, testWorkerConfig(t, `{"default":"allow"}`))
		// Ensure the periodic pull cannot fire. Close must obtain the final
		// cumulative snapshot in the graceful shutdown response.
		w.StartTrafficSyncEvery(supervisor, time.Hour)
		if err := workerproto.WriteFrame(data,
			workerTestFrame(t, "203.0.113.7", 6, uint16(443+boot))); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			snapshot, err := w.TrafficSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.TXPackets == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("boot %d traffic was not observed: %+v", boot+1, snapshot)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close boot %d: %v", boot+1, err)
		}
	}

	supervisor.Close()
	got, err := netpol.ReadTrafficSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.TXPackets != 2 || len(got.Entries) != 2 {
		t.Fatalf("lifetime traffic after two workers = %+v", got)
	}
}

func TestNetWorkerMalformedFrameTearsDownLink(t *testing.T) {
	w, data := startInProcessWorker(t, testWorkerConfig(t, `{"default":"allow"}`), true)

	// Declare a frame larger than MaxFrame: the pump must close BOTH
	// ends, the worker unwinds, and control calls start failing.
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(workerproto.MaxFrame+1))
	if _, err := data.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	w.client.Timeout = 2 * time.Second
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := w.Forwards(); err != nil {
			return // worker gone, as required
		}
		if time.Now().After(deadline) {
			t.Fatal("worker survived an oversized frame")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestNetWorkerNonceMismatchRefused(t *testing.T) {
	ctrlSup, ctrlWrk := net.Pipe()
	dataSup, dataWrk := net.Pipe()
	workerErr := make(chan error, 1)
	go func() { workerErr <- networkworker.Run(ctrlWrk, dataWrk) }()
	defer func() {
		_ = ctrlSup.Close()
		_ = dataSup.Close()
	}()

	nonce := testWorkerNonce(t)
	cfg := testWorkerConfig(t, `{"default":"allow"}`)
	if err := workerproto.SendHandshake(ctrlSup, workerproto.RoleNet, nonce, cfg); err != nil {
		t.Fatal(err)
	}
	// Wrong nonce on the data channel: cross-wiring must be fatal.
	if err := workerproto.WriteNonce(dataSup, testWorkerNonce(t)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-workerErr:
		if err == nil {
			t.Fatal("worker accepted a mismatched data channel")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker hung on nonce mismatch")
	}
}

func TestNetWorkerPolicyGenerationOrder(t *testing.T) {
	w, _ := startInProcessWorker(t, testWorkerConfig(t, `{"default":"allow"}`))
	deny, _ := netpol.Parse([]byte(`{"default":"deny"}`))

	// First transition is generation 1
	if err := w.SetPolicy(deny); err != nil {
		t.Fatal(err)
	}
	// Second is generation 2
	if err := w.SetPolicy(deny); err != nil {
		t.Fatal(err)
	}
	// Worker-side out-of-order prepare is rejected
	raw, _ := netpol.Marshal(deny)
	err := w.client.Call(networkworker.OpPolicyPrepare, networkworker.PolicyPrepareRequest{Generation: 99, Transaction: "out-of-order", Policy: raw}, nil)
	if err == nil {
		t.Fatal("out-of-order generation accepted")
	}
}

type policyRPCStep struct {
	op     string
	handle func(workerproto.Request) (any, error)
}

type portRPCStep struct {
	op     string
	handle func(workerproto.Request) (any, error)
}

const wPortTestTimeout = 500 * time.Millisecond

func startPortTransactionRPC(t *testing.T, steps []portRPCStep) *Worker {
	t.Helper()
	sup, childConn := net.Pipe()
	var mu sync.Mutex
	next := 0
	dispatch := func(op string) workerproto.Handler {
		return func(req workerproto.Request) (any, error) {
			mu.Lock()
			if next >= len(steps) {
				mu.Unlock()
				return nil, fmt.Errorf("unexpected port operation %s", op)
			}
			stepIndex := next
			step := steps[stepIndex]
			next++
			mu.Unlock()
			if step.op != op {
				return nil, fmt.Errorf("port operation %d = %s, want %s", stepIndex+1, op, step.op)
			}
			return step.handle(req)
		}
	}
	handlers := make(map[string]workerproto.Handler)
	ordered := make(map[string]bool)
	for _, op := range []string{
		networkworker.OpPortPublish,
		networkworker.OpPortUnpublish,
		networkworker.OpPortStatus,
		networkworker.OpPortList,
	} {
		handlers[op] = dispatch(op)
		ordered[op] = true
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- workerproto.ServeRequestsWithOptions(childConn, handlers,
			workerproto.ServeOptions{OrderedOps: ordered})
	}()
	client := workerproto.NewClient(sup)
	client.Timeout = wPortTestTimeout
	w := &Worker{client: client, lifecycle: worker.NewLifecycle()}
	t.Cleanup(func() {
		_ = client.Close()
		_ = childConn.Close()
		select {
		case <-serveErr:
		case <-time.After(time.Second):
			t.Error("port RPC server did not stop")
		}
		mu.Lock()
		defer mu.Unlock()
		if next != len(steps) {
			t.Errorf("port script consumed %d/%d steps", next, len(steps))
		}
	})
	return w
}

func decodePortPublish(t *testing.T, req workerproto.Request) networkworker.PortPublishRequest {
	t.Helper()
	var body networkworker.PortPublishRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		t.Errorf("decode port publish: %v", err)
	}
	return body
}

func decodePortStatus(t *testing.T, req workerproto.Request) networkworker.PortStatusRequest {
	t.Helper()
	var body networkworker.PortStatusRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		t.Errorf("decode port status: %v", err)
	}
	return body
}

func decodePortUnpublish(t *testing.T, req workerproto.Request) networkworker.PortUnpublishRequest {
	t.Helper()
	var body networkworker.PortUnpublishRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		t.Errorf("decode port unpublish: %v", err)
	}
	return body
}

func TestNetWorkerPortTransactionsRecoverLostResponses(t *testing.T) {
	const local = "127.0.0.1:18090"
	const remote = "192.168.127.2:8080"

	t.Run("status confirms lost publish response", func(t *testing.T) {
		var transaction string
		w := startPortTransactionRPC(t, []portRPCStep{
			{op: networkworker.OpPortPublish, handle: func(req workerproto.Request) (any, error) {
				body := decodePortPublish(t, req)
				transaction = body.Transaction
				return nil, errors.New("simulated lost publish response after apply")
			}},
			{op: networkworker.OpPortStatus, handle: func(req workerproto.Request) (any, error) {
				if got := decodePortStatus(t, req).Transaction; got != transaction {
					t.Errorf("status transaction = %q, want %q", got, transaction)
				}
				return networkworker.PortStatusResponse{Transaction: transaction, State: networkworker.PortStateApplied}, nil
			}},
		})
		if err := w.Publish("tcp", local, remote); err != nil {
			t.Fatalf("lost publish response: %v", err)
		}
	})

	t.Run("lost status response retries same transaction", func(t *testing.T) {
		var transaction string
		w := startPortTransactionRPC(t, []portRPCStep{
			{op: networkworker.OpPortPublish, handle: func(req workerproto.Request) (any, error) {
				transaction = decodePortPublish(t, req).Transaction
				return nil, errors.New("simulated lost publish response after apply")
			}},
			{op: networkworker.OpPortStatus, handle: func(req workerproto.Request) (any, error) {
				if got := decodePortStatus(t, req).Transaction; got != transaction {
					t.Errorf("status transaction = %q, want %q", got, transaction)
				}
				return nil, errors.New("simulated lost status response")
			}},
			{op: networkworker.OpPortPublish, handle: func(req workerproto.Request) (any, error) {
				if got := decodePortPublish(t, req).Transaction; got != transaction {
					t.Errorf("retried transaction = %q, want %q", got, transaction)
				}
				return networkworker.PortStatusResponse{Transaction: transaction, State: networkworker.PortStateApplied}, nil
			}},
		})
		if err := w.Publish("tcp", local, remote); err != nil {
			t.Fatalf("lost status response: %v", err)
		}
	})

	t.Run("status confirms lost unpublish response", func(t *testing.T) {
		var transaction string
		w := startPortTransactionRPC(t, []portRPCStep{
			{op: networkworker.OpPortUnpublish, handle: func(req workerproto.Request) (any, error) {
				body := decodePortUnpublish(t, req)
				transaction = body.Transaction
				return nil, errors.New("simulated lost unpublish response after apply")
			}},
			{op: networkworker.OpPortStatus, handle: func(req workerproto.Request) (any, error) {
				if got := decodePortStatus(t, req).Transaction; got != transaction {
					t.Errorf("status transaction = %q, want %q", got, transaction)
				}
				return networkworker.PortStatusResponse{Transaction: transaction, State: networkworker.PortStateApplied}, nil
			}},
		})
		if err := w.Unpublish("tcp", local); err != nil {
			t.Fatalf("lost unpublish response: %v", err)
		}
	})

	t.Run("list reconciles lost replies", func(t *testing.T) {
		var transaction string
		w := startPortTransactionRPC(t, []portRPCStep{
			{op: networkworker.OpPortPublish, handle: func(req workerproto.Request) (any, error) {
				transaction = decodePortPublish(t, req).Transaction
				return nil, errors.New("injected response loss")
			}},
			{op: networkworker.OpPortStatus, handle: func(workerproto.Request) (any, error) {
				return networkworker.PortStatusResponse{Transaction: transaction, State: networkworker.PortStateUnknown}, nil
			}},
			{op: networkworker.OpPortPublish, handle: func(req workerproto.Request) (any, error) {
				if got := decodePortPublish(t, req).Transaction; got != transaction {
					t.Errorf("retried transaction = %q, want %q", got, transaction)
				}
				return nil, errors.New("injected retry response loss")
			}},
			{op: networkworker.OpPortStatus, handle: func(workerproto.Request) (any, error) {
				return networkworker.PortStatusResponse{Transaction: transaction, State: networkworker.PortStateUnknown}, nil
			}},
			{op: networkworker.OpPortList, handle: func(workerproto.Request) (any, error) {
				return []vnet.Forward{{Protocol: "tcp", Local: local, Remote: remote}}, nil
			}},
		})
		if err := w.Publish("tcp", local, remote); err != nil {
			t.Fatalf("list reconciliation: %v", err)
		}
	})

	t.Run("list proves failed publish left prior state", func(t *testing.T) {
		var transaction string
		w := startPortTransactionRPC(t, []portRPCStep{
			{op: networkworker.OpPortPublish, handle: func(req workerproto.Request) (any, error) {
				transaction = decodePortPublish(t, req).Transaction
				return nil, errors.New("injected publish failure")
			}},
			{op: networkworker.OpPortStatus, handle: func(workerproto.Request) (any, error) {
				return networkworker.PortStatusResponse{Transaction: transaction, State: networkworker.PortStateUnknown}, nil
			}},
			{op: networkworker.OpPortPublish, handle: func(workerproto.Request) (any, error) {
				return nil, errors.New("injected publish retry failure")
			}},
			{op: networkworker.OpPortStatus, handle: func(workerproto.Request) (any, error) {
				return networkworker.PortStatusResponse{Transaction: transaction, State: networkworker.PortStateUnknown}, nil
			}},
			{op: networkworker.OpPortList, handle: func(workerproto.Request) (any, error) {
				return []vnet.Forward{}, nil
			}},
		})
		if err := w.Publish("tcp", local, remote); err == nil {
			t.Fatal("failed publish reported success")
		}
	})
}

func startPolicyTransactionRPC(t *testing.T, steps []policyRPCStep) *Worker {
	t.Helper()
	sup, childConn := net.Pipe()
	var mu sync.Mutex
	next := 0
	dispatch := func(op string) workerproto.Handler {
		return func(req workerproto.Request) (any, error) {
			mu.Lock()
			if next >= len(steps) {
				mu.Unlock()
				return nil, fmt.Errorf("unexpected policy operation %s", op)
			}
			stepIndex := next
			step := steps[stepIndex]
			next++
			mu.Unlock()
			if step.op != op {
				return nil, fmt.Errorf("policy operation %d = %s, want %s", stepIndex+1, op, step.op)
			}
			return step.handle(req)
		}
	}
	handlers := map[string]workerproto.Handler{}
	ordered := map[string]bool{}
	for _, op := range []string{
		networkworker.OpPolicyPrepare,
		networkworker.OpPolicyCommit,
		networkworker.OpPolicyAbort,
		networkworker.OpPolicyStatus,
	} {
		handlers[op] = dispatch(op)
		ordered[op] = true
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- workerproto.ServeRequestsWithOptions(childConn, handlers,
			workerproto.ServeOptions{OrderedOps: ordered})
	}()
	client := workerproto.NewClient(sup)
	client.Timeout = wPolicyTestTimeout
	w := &Worker{client: client, lifecycle: worker.NewLifecycle()}
	t.Cleanup(func() {
		_ = client.Close()
		_ = childConn.Close()
		select {
		case <-serveErr:
		case <-time.After(time.Second):
			t.Error("policy RPC server did not stop")
		}
		mu.Lock()
		defer mu.Unlock()
		if next != len(steps) {
			t.Errorf("policy script consumed %d/%d steps", next, len(steps))
		}
	})
	return w
}

func decodePolicyPrepare(t *testing.T, req workerproto.Request) networkworker.PolicyPrepareRequest {
	t.Helper()
	var body networkworker.PolicyPrepareRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		t.Errorf("decode policy prepare: %v", err)
	}
	return body
}

func decodePolicyGeneration(t *testing.T, req workerproto.Request) networkworker.PolicyGenerationRequest {
	t.Helper()
	var body networkworker.PolicyGenerationRequest
	if err := workerproto.DecodeBody(req, &body); err != nil {
		t.Errorf("decode policy generation: %v", err)
	}
	return body
}

func TestNetWorkerPolicyTransactionsRecoverFromFailures(t *testing.T) {
	deny := mustTestPolicy(t, `{"default":"deny"}`)
	allow := mustTestPolicy(t, `{"default":"allow","allowLocal":true}`)

	t.Run("rejected prepare does not consume generation", func(t *testing.T) {
		var rejectedTxn, committedTxn string
		steps := []policyRPCStep{
			{op: networkworker.OpPolicyStatus, handle: func(req workerproto.Request) (any, error) {
				if got := decodePolicyGeneration(t, req).Transaction; got != "" {
					t.Errorf("initial status transaction = %q", got)
				}
				return networkworker.PolicyStatusResponse{State: networkworker.PolicyStateCurrent}, nil
			}},
			{op: networkworker.OpPolicyPrepare, handle: func(req workerproto.Request) (any, error) {
				body := decodePolicyPrepare(t, req)
				rejectedTxn = body.Transaction
				if body.Generation != 1 || rejectedTxn == "" {
					t.Errorf("rejected prepare = %+v", body)
				}
				return nil, errors.New("injected prepare rejection")
			}},
			{op: networkworker.OpPolicyStatus, handle: func(req workerproto.Request) (any, error) {
				if got := decodePolicyGeneration(t, req).Transaction; got != rejectedTxn {
					t.Errorf("prepare readback transaction = %q, want %q", got, rejectedTxn)
				}
				return networkworker.PolicyStatusResponse{State: networkworker.PolicyStateUnknown}, nil
			}},
			{op: networkworker.OpPolicyStatus, handle: func(req workerproto.Request) (any, error) {
				return networkworker.PolicyStatusResponse{State: networkworker.PolicyStateCurrent}, nil
			}},
			{op: networkworker.OpPolicyPrepare, handle: func(req workerproto.Request) (any, error) {
				body := decodePolicyPrepare(t, req)
				committedTxn = body.Transaction
				if body.Generation != 1 || committedTxn == "" || committedTxn == rejectedTxn {
					t.Errorf("retry prepare = %+v after %q", body, rejectedTxn)
				}
				return networkworker.PolicyStatusResponse{
					State: networkworker.PolicyStatePrepared, PendingGeneration: 1,
					PendingTransaction: committedTxn,
				}, nil
			}},
			{op: networkworker.OpPolicyCommit, handle: func(req workerproto.Request) (any, error) {
				body := decodePolicyGeneration(t, req)
				if body.Generation != 1 || body.Transaction != committedTxn {
					t.Errorf("retry commit = %+v", body)
				}
				return networkworker.PolicyStatusResponse{
					State: networkworker.PolicyStateCommitted, Generation: 1,
					Transaction: committedTxn,
				}, nil
			}},
		}
		w := startPolicyTransactionRPC(t, steps)
		if err := w.SetPolicy(deny); err == nil {
			t.Fatal("rejected prepare reported success")
		}
		if w.gen != 0 {
			t.Fatalf("failed prepare advanced supervisor generation to %d", w.gen)
		}
		if err := w.SetPolicy(deny); err != nil {
			t.Fatalf("retry after rejected prepare: %v", err)
		}
		if w.gen != 1 {
			t.Fatalf("retry generation = %d, want 1", w.gen)
		}
	})

	t.Run("commit error retries same transaction", func(t *testing.T) {
		var txn string
		steps := []policyRPCStep{
			{op: networkworker.OpPolicyStatus, handle: func(workerproto.Request) (any, error) {
				return networkworker.PolicyStatusResponse{State: networkworker.PolicyStateCurrent}, nil
			}},
			{op: networkworker.OpPolicyPrepare, handle: func(req workerproto.Request) (any, error) {
				body := decodePolicyPrepare(t, req)
				txn = body.Transaction
				return networkworker.PolicyStatusResponse{State: networkworker.PolicyStatePrepared}, nil
			}},
			{op: networkworker.OpPolicyCommit, handle: func(req workerproto.Request) (any, error) {
				if got := decodePolicyGeneration(t, req).Transaction; got != txn {
					t.Errorf("first commit transaction = %q, want %q", got, txn)
				}
				return nil, errors.New("injected commit failure")
			}},
			{op: networkworker.OpPolicyStatus, handle: func(req workerproto.Request) (any, error) {
				if got := decodePolicyGeneration(t, req).Transaction; got != txn {
					t.Errorf("commit readback transaction = %q, want %q", got, txn)
				}
				return networkworker.PolicyStatusResponse{
					State:             networkworker.PolicyStatePrepared,
					PendingGeneration: 1, PendingTransaction: txn,
				}, nil
			}},
			{op: networkworker.OpPolicyCommit, handle: func(req workerproto.Request) (any, error) {
				body := decodePolicyGeneration(t, req)
				if body.Generation != 1 || body.Transaction != txn {
					t.Errorf("retry commit = %+v", body)
				}
				return nil, nil
			}},
		}
		w := startPolicyTransactionRPC(t, steps)
		if err := w.SetPolicy(deny); err != nil {
			t.Fatal(err)
		}
		if w.gen != 1 {
			t.Fatalf("generation = %d, want 1", w.gen)
		}
	})

	t.Run("lost commit response resolved by status", func(t *testing.T) {
		var firstTxn, secondTxn string
		steps := []policyRPCStep{
			{op: networkworker.OpPolicyStatus, handle: func(workerproto.Request) (any, error) {
				return networkworker.PolicyStatusResponse{State: networkworker.PolicyStateCurrent}, nil
			}},
			{op: networkworker.OpPolicyPrepare, handle: func(req workerproto.Request) (any, error) {
				firstTxn = decodePolicyPrepare(t, req).Transaction
				return nil, nil
			}},
			{op: networkworker.OpPolicyCommit, handle: func(req workerproto.Request) (any, error) {
				if got := decodePolicyGeneration(t, req).Transaction; got != firstTxn {
					t.Errorf("delayed commit transaction = %q, want %q", got, firstTxn)
				}
				return nil, errors.New("simulated lost commit response after apply")
			}},
			{op: networkworker.OpPolicyStatus, handle: func(req workerproto.Request) (any, error) {
				if got := decodePolicyGeneration(t, req).Transaction; got != firstTxn {
					t.Errorf("lost commit readback = %q, want %q", got, firstTxn)
				}
				return networkworker.PolicyStatusResponse{
					State:      networkworker.PolicyStateCommitted,
					Generation: 1, Transaction: firstTxn,
				}, nil
			}},
			{op: networkworker.OpPolicyStatus, handle: func(workerproto.Request) (any, error) {
				return networkworker.PolicyStatusResponse{
					State:      networkworker.PolicyStateCurrent,
					Generation: 1, Transaction: firstTxn,
				}, nil
			}},
			{op: networkworker.OpPolicyPrepare, handle: func(req workerproto.Request) (any, error) {
				body := decodePolicyPrepare(t, req)
				secondTxn = body.Transaction
				if body.Generation != 2 || secondTxn == firstTxn {
					t.Errorf("second prepare = %+v after %q", body, firstTxn)
				}
				return nil, nil
			}},
			{op: networkworker.OpPolicyCommit, handle: func(req workerproto.Request) (any, error) {
				body := decodePolicyGeneration(t, req)
				if body.Generation != 2 || body.Transaction != secondTxn {
					t.Errorf("second commit = %+v", body)
				}
				return nil, nil
			}},
		}
		w := startPolicyTransactionRPC(t, steps)
		if err := w.SetPolicy(deny); err != nil {
			t.Fatalf("lost commit response: %v", err)
		}
		if err := w.SetPolicy(allow); err != nil {
			t.Fatalf("call after reconciled response loss: %v", err)
		}
		if w.gen != 2 {
			t.Fatalf("post-timeout generation = %d, want 2", w.gen)
		}
	})

	t.Run("abort readback recognizes a committed transaction", func(t *testing.T) {
		var txn string
		steps := []policyRPCStep{
			{op: networkworker.OpPolicyStatus, handle: func(workerproto.Request) (any, error) {
				return networkworker.PolicyStatusResponse{State: networkworker.PolicyStateCurrent}, nil
			}},
			{op: networkworker.OpPolicyPrepare, handle: func(req workerproto.Request) (any, error) {
				txn = decodePolicyPrepare(t, req).Transaction
				return nil, nil
			}},
			{op: networkworker.OpPolicyCommit, handle: func(workerproto.Request) (any, error) {
				return nil, errors.New("injected commit rejection")
			}},
			{op: networkworker.OpPolicyStatus, handle: func(workerproto.Request) (any, error) {
				return networkworker.PolicyStatusResponse{
					State:             networkworker.PolicyStatePrepared,
					PendingGeneration: 1, PendingTransaction: txn,
				}, nil
			}},
			{op: networkworker.OpPolicyCommit, handle: func(req workerproto.Request) (any, error) {
				if got := decodePolicyGeneration(t, req).Transaction; got != txn {
					t.Errorf("delayed retry transaction = %q, want %q", got, txn)
				}
				return nil, errors.New("simulated lost retry response after apply")
			}},
			{op: networkworker.OpPolicyStatus, handle: func(workerproto.Request) (any, error) {
				return nil, errors.New("injected status response loss")
			}},
			{op: networkworker.OpPolicyAbort, handle: func(req workerproto.Request) (any, error) {
				body := decodePolicyGeneration(t, req)
				if body.Generation != 1 || body.Transaction != txn {
					t.Errorf("abort readback = %+v", body)
				}
				return networkworker.PolicyStatusResponse{
					State:      networkworker.PolicyStateCommitted,
					Generation: 1, Transaction: txn,
				}, nil
			}},
		}
		w := startPolicyTransactionRPC(t, steps)
		if err := w.SetPolicy(deny); err != nil {
			t.Fatalf("committed transaction reported failure: %v", err)
		}
		if w.gen != 1 {
			t.Fatalf("generation = %d, want 1", w.gen)
		}
	})

	t.Run("failed commits abort and next call reuses generation", func(t *testing.T) {
		var firstTxn, secondTxn string
		steps := []policyRPCStep{
			{op: networkworker.OpPolicyStatus, handle: func(workerproto.Request) (any, error) {
				return networkworker.PolicyStatusResponse{State: networkworker.PolicyStateCurrent}, nil
			}},
			{op: networkworker.OpPolicyPrepare, handle: func(req workerproto.Request) (any, error) {
				firstTxn = decodePolicyPrepare(t, req).Transaction
				return nil, nil
			}},
			{op: networkworker.OpPolicyCommit, handle: func(workerproto.Request) (any, error) {
				return nil, errors.New("injected persistent commit failure")
			}},
			{op: networkworker.OpPolicyStatus, handle: func(workerproto.Request) (any, error) {
				return networkworker.PolicyStatusResponse{
					State:             networkworker.PolicyStatePrepared,
					PendingGeneration: 1, PendingTransaction: firstTxn,
				}, nil
			}},
			{op: networkworker.OpPolicyCommit, handle: func(workerproto.Request) (any, error) {
				return nil, errors.New("injected persistent commit failure")
			}},
			{op: networkworker.OpPolicyStatus, handle: func(workerproto.Request) (any, error) {
				return networkworker.PolicyStatusResponse{
					State:             networkworker.PolicyStatePrepared,
					PendingGeneration: 1, PendingTransaction: firstTxn,
				}, nil
			}},
			{op: networkworker.OpPolicyAbort, handle: func(req workerproto.Request) (any, error) {
				if got := decodePolicyGeneration(t, req).Transaction; got != firstTxn {
					t.Errorf("abort transaction = %q, want %q", got, firstTxn)
				}
				return networkworker.PolicyStatusResponse{State: networkworker.PolicyStateUnknown}, nil
			}},
			{op: networkworker.OpPolicyStatus, handle: func(workerproto.Request) (any, error) {
				return networkworker.PolicyStatusResponse{State: networkworker.PolicyStateCurrent}, nil
			}},
			{op: networkworker.OpPolicyPrepare, handle: func(req workerproto.Request) (any, error) {
				body := decodePolicyPrepare(t, req)
				secondTxn = body.Transaction
				if body.Generation != 1 || secondTxn == firstTxn {
					t.Errorf("retry prepare = %+v after %q", body, firstTxn)
				}
				return nil, nil
			}},
			{op: networkworker.OpPolicyCommit, handle: func(req workerproto.Request) (any, error) {
				body := decodePolicyGeneration(t, req)
				if body.Generation != 1 || body.Transaction != secondTxn {
					t.Errorf("retry commit = %+v", body)
				}
				return nil, nil
			}},
		}
		w := startPolicyTransactionRPC(t, steps)
		if err := w.SetPolicy(deny); err == nil {
			t.Fatal("failed commits reported success")
		}
		if w.gen != 0 {
			t.Fatalf("failed commits advanced generation to %d", w.gen)
		}
		if err := w.SetPolicy(deny); err != nil {
			t.Fatalf("retry after aborted commit: %v", err)
		}
		if w.gen != 1 {
			t.Fatalf("retry generation = %d, want 1", w.gen)
		}
	})
}

// Transport-level late-response discard is covered in workerproto. These
// transaction tests inject the resulting ambiguous error directly, keeping
// policy reconciliation deterministic under the race detector and loaded CI.
const wPolicyTestTimeout = 500 * time.Millisecond

// TestNetWorkerHelperProcess IS the worker when re-executed by
// TestNetWorkerReExec (helper-process pattern): it serves on the real
// inherited fds 3/4 and exits 0 on graceful shutdown.
func TestNetWorkerHelperProcess(t *testing.T) {
	if os.Getenv("GANTRY_TEST_NET_WORKER") != "1" {
		return
	}
	workertest.AssertStdinUnreadable()
	os.Exit(networkworker.Cmd())
}

// TestNetWorkerReExec validates the real descriptor-inheritance path:
// the worker runs as a separate OS process (this test binary) with the
// control/data socketpairs as fds 3/4, exactly like production spawn.
func TestNetWorkerReExec(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctrlSup, ctrlWrk, err := worker.SocketpairConns()
	if err != nil {
		t.Fatal(err)
	}
	dataSup, dataWrk, err := worker.SocketpairConns()
	if err != nil {
		t.Fatal(err)
	}
	ctrlFile, err := worker.ConnFile(ctrlWrk)
	if err != nil {
		t.Fatal(err)
	}
	dataFile, err := worker.ConnFile(dataWrk)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(exe, "-test.run", "^TestNetWorkerHelperProcess$")
	cmd.Env = append(os.Environ(), "GANTRY_TEST_NET_WORKER=1")
	cmd.ExtraFiles = []*os.File{ctrlFile, dataFile}
	var outBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &outBuf, &outBuf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = ctrlWrk.Close()
	_ = dataWrk.Close()
	_ = ctrlFile.Close()
	_ = dataFile.Close()

	nonce := testWorkerNonce(t)
	cfg := testWorkerConfig(t, `{"default":"allow"}`)
	if err := workerproto.SendHandshake(ctrlSup, workerproto.RoleNet, nonce, cfg); err != nil {
		t.Fatalf("handshake: %v\n%s", err, outBuf.String())
	}
	if err := workerproto.WriteNonce(dataSup, nonce); err != nil {
		t.Fatal(err)
	}
	var ack workerproto.Response
	_ = ctrlSup.SetReadDeadline(time.Now().Add(15 * time.Second))
	if err := workerproto.ReadMessage(ctrlSup, &ack); err != nil {
		t.Fatalf("ack: %v\n%s", err, outBuf.String())
	}
	if !ack.OK {
		t.Fatalf("worker refused bootstrap:\n%s", outBuf.String())
	}

	client := workerproto.NewClient(ctrlSup)
	var published networkworker.PortStatusResponse
	if err := client.Call(networkworker.OpPortPublish, networkworker.PortPublishRequest{
		Transaction: "reexec-publish",
		Proto:       "tcp",
		Local:       "127.0.0.1:18082",
		Remote:      "192.168.127.2:8082",
	}, &published); err != nil {
		t.Fatalf("publish over re-exec: %v\n%s", err, outBuf.String())
	}
	if published.State != networkworker.PortStateApplied {
		t.Fatalf("publish result = %+v", published)
	}
	if err := client.Call(networkworker.OpShutdown, nil, nil); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	_ = ctrlSup.Close()
	_ = dataSup.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("worker exit: %v\n%s", err, outBuf.String())
	}
}

func TestDupConnFilesClosesSourcesAndPartialDuplicates(t *testing.T) {
	source, sourcePeer, err := worker.SocketpairConns()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sourcePeer.Close() }()
	unsupported, unsupportedPeer := net.Pipe()
	defer func() { _ = unsupportedPeer.Close() }()

	files, err := worker.DupConnFiles(source, unsupported)
	if err == nil {
		t.Fatal("partial duplication unexpectedly succeeded")
	}
	if files != nil {
		t.Fatalf("partial duplication returned files: %v", files)
	}
	for name, peer := range map[string]net.Conn{
		"real socket source and duplicate": sourcePeer,
		"unsupported source":               unsupportedPeer,
	} {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		var one [1]byte
		n, readErr := peer.Read(one[:])
		if n != 0 || !errors.Is(readErr, io.EOF) {
			t.Errorf("%s not closed: read n=%d err=%v", name, n, readErr)
		}
	}
}

func TestSpawnNetWorkerRejectsUnusableDiagnosticSink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "worker-net.log")
	control, data, process, diagnostics, err := spawnNetWorkerProcess(path, "off")
	if control != nil || data != nil || process != nil || diagnostics != nil {
		t.Fatalf("failed spawn returned resources: control=%v data=%v process=%v diagnostics=%v", control, data, process, diagnostics)
	}
	if err == nil || !strings.Contains(err.Error(), "open network worker log") {
		t.Fatalf("spawn error = %v, want diagnostic-sink failure", err)
	}
}

func TestWorkerEnvironmentDoesNotInheritHostAuthority(t *testing.T) {
	t.Setenv("PATH", "/host/tools")
	t.Setenv("HOME", "/host/home")
	t.Setenv("TMPDIR", "/host/tmp")
	t.Setenv("GANTRY_SECRET_TEST", "must-not-cross")
	t.Setenv("GANTRY_DEBUG_RTC", "1")
	t.Setenv("GANTRY_PREFAULT_RAM", "1")
	t.Setenv("GANTRY_BOOT_PROFILE", "1")
	t.Setenv("GANTRY_VHOST_STATS", "1")
	t.Setenv("GANTRY_VIRTIO_MEM", "true")

	want := []string{"GANTRY_DEBUG_RTC=1", "GANTRY_PREFAULT_RAM=1", "GANTRY_BOOT_PROFILE=1", "GANTRY_VHOST_STATS=1", "GANTRY_VIRTIO_MEM=1"}
	if got := worker.Env(); !slices.Equal(got, want) {
		t.Fatalf("worker environment = %v, want only the non-secret debug switches %v", got, want)
	}
	if got := workerEnv(); !slices.Equal(got, append(slices.Clone(want), "GODEBUG=netdns=go")) {
		t.Fatalf("network worker environment = %v, want debug switches + pure-Go resolver", got)
	}
}

func TestWorkerEnvironmentCarriesNothingByDefault(t *testing.T) {
	t.Setenv("GANTRY_DEBUG_RTC", "")
	t.Setenv("GANTRY_PREFAULT_RAM", "")
	t.Setenv("GANTRY_BOOT_PROFILE", "")
	t.Setenv("GANTRY_VHOST_STATS", "")
	t.Setenv("GANTRY_VIRTIO_MEM", "")
	if got := worker.Env(); len(got) != 0 {
		t.Fatalf("worker environment = %v, want empty", got)
	}
}
