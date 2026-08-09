//go:build linux || darwin

package sandbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/workerconf"
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

// startInProcessWorker drives runNetWorker on net.Pipe channels and
// performs the supervisor-side handshake + nonce, returning the ready
// backend. The worker goroutine exits when the backend is closed.
// expectDeath tolerates an error exit in cleanup (the malformed-frame
// test kills the worker on purpose).
func startInProcessWorker(t *testing.T, cfg netWorkerConfig, expectDeath ...bool) (*netWorker, net.Conn) {
	t.Helper()
	ctrlSup, ctrlWrk := net.Pipe()
	dataSup, dataWrk := net.Pipe()
	workerErr := make(chan error, 1)
	go func() { workerErr <- runNetWorker(ctrlWrk, dataWrk) }()

	nonce := workerproto.NewNonce()
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
	w := &netWorker{
		client: workerproto.NewClient(ctrlSup),
		data:   dataSup,
		dead:   make(chan struct{}),
	}
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

func testWorkerConfig(t *testing.T, policyJSON string) netWorkerConfig {
	t.Helper()
	return netWorkerConfig{
		GuestMAC:    testWorkerMAC,
		Policy:      json.RawMessage(policyJSON),
		TrafficPath: filepath.Join(t.TempDir(), "traffic.json"),
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

// TestNetWorkerDoneConsumptionDoesNotBlockClose is the failure-teardown
// regression. Done used to carry one buffered error value: the daemon consumed
// it in its fatal-worker select, then deferred Close waited forever for a
// second value after trying to kill an already-reaped process. A closed channel
// must broadcast death independently of Err retrieval.
func TestNetWorkerDoneConsumptionDoesNotBlockClose(t *testing.T) {
	want := errors.New("worker failed")
	var kills atomic.Int32
	w := &netWorker{
		dead: make(chan struct{}),
		kill: func() error {
			kills.Add(1)
			return nil
		},
	}
	w.setDead(want)

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
	w := &netWorker{
		data: data,
		dead: make(chan struct{}),
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
	go func() { workerErr <- runNetWorker(ctrlWrk, dataWrk) }()
	defer func() {
		_ = ctrlSup.Close()
		_ = dataSup.Close()
	}()

	nonce := workerproto.NewNonce()
	cfg := testWorkerConfig(t, `{"default":"allow"}`)
	if err := workerproto.SendHandshake(ctrlSup, workerproto.RoleNet, nonce, cfg); err != nil {
		t.Fatal(err)
	}
	// Wrong nonce on the data channel: cross-wiring must be fatal.
	if err := workerproto.WriteNonce(dataSup, workerproto.NewNonce()); err != nil {
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
	err := w.client.Call("policy.prepare", policyPrepareRequest{Generation: 99, Transaction: "out-of-order", Policy: raw}, nil)
	if err == nil {
		t.Fatal("out-of-order generation accepted")
	}
}

func newPolicyTransactionState(t *testing.T) (*netWorkerState, *netpol.Policy) {
	t.Helper()
	initial := mustTestPolicy(t, `{"default":"allow","allowLocal":true}`)
	raw, err := netpol.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	return &netWorkerState{
		policy: initial, currentDigest: sha256.Sum256(raw),
	}, initial
}

func startPolicyTransactionRPC(t *testing.T, state *netWorkerState, overrides map[string]workerproto.Handler) *netWorker {
	t.Helper()
	sup, worker := net.Pipe()
	handlers := map[string]workerproto.Handler{
		"policy.prepare": state.preparePolicy,
		"policy.commit":  state.commitPolicy,
		"policy.abort":   state.abortPolicy,
		"policy.status":  state.policyStatus,
	}
	for op, handler := range overrides {
		handlers[op] = handler
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- workerproto.ServeRequestsWithOptions(worker, handlers, workerproto.ServeOptions{
			OrderedOps: map[string]bool{
				"policy.prepare": true,
				"policy.commit":  true,
				"policy.abort":   true,
				"policy.status":  true,
			},
		})
	}()
	client := workerproto.NewClient(sup)
	client.Timeout = wPolicyTestTimeout
	w := &netWorker{client: client, dead: make(chan struct{})}
	t.Cleanup(func() {
		_ = client.Close()
		_ = worker.Close()
		select {
		case <-serveErr:
		case <-time.After(time.Second):
			t.Error("policy RPC server did not stop")
		}
	})
	return w
}

func TestNetWorkerPolicyTransactionsRecoverFromFailures(t *testing.T) {
	deny := mustTestPolicy(t, `{"default":"deny"}`)
	allow := mustTestPolicy(t, `{"default":"allow","allowLocal":true}`)

	t.Run("rejected prepare does not consume generation", func(t *testing.T) {
		state, live := newPolicyTransactionState(t)
		var reject atomic.Bool
		reject.Store(true)
		w := startPolicyTransactionRPC(t, state, map[string]workerproto.Handler{
			"policy.prepare": func(req workerproto.Request) (any, error) {
				if reject.Swap(false) {
					return nil, errors.New("injected prepare rejection")
				}
				return state.preparePolicy(req)
			},
		})
		if err := w.SetPolicy(deny); err == nil {
			t.Fatal("rejected prepare reported success")
		}
		if state.gen != 0 || w.gen != 0 || !live.Allows([4]byte{8, 8, 8, 8}, 6, 443) {
			t.Fatalf("failed prepare changed generation/policy: worker=%d supervisor=%d", state.gen, w.gen)
		}
		if err := w.SetPolicy(deny); err != nil {
			t.Fatalf("retry after rejected prepare: %v", err)
		}
		if state.gen != 1 || w.gen != 1 || live.Allows([4]byte{8, 8, 8, 8}, 6, 443) {
			t.Fatalf("retry did not commit generation 1: worker=%d supervisor=%d", state.gen, w.gen)
		}
	})

	t.Run("commit error retries same transaction", func(t *testing.T) {
		state, live := newPolicyTransactionState(t)
		var commits atomic.Int32
		w := startPolicyTransactionRPC(t, state, map[string]workerproto.Handler{
			"policy.commit": func(req workerproto.Request) (any, error) {
				if commits.Add(1) == 1 {
					return nil, errors.New("injected commit failure")
				}
				return state.commitPolicy(req)
			},
		})
		if err := w.SetPolicy(deny); err != nil {
			t.Fatal(err)
		}
		if commits.Load() != 2 || state.gen != 1 || w.gen != 1 || live.Allows([4]byte{8, 8, 8, 8}, 6, 443) {
			t.Fatalf("commit retry did not converge: calls=%d worker=%d supervisor=%d", commits.Load(), state.gen, w.gen)
		}
	})

	t.Run("lost commit response resolved by status", func(t *testing.T) {
		state, live := newPolicyTransactionState(t)
		var first atomic.Bool
		first.Store(true)
		w := startPolicyTransactionRPC(t, state, map[string]workerproto.Handler{
			"policy.commit": func(req workerproto.Request) (any, error) {
				out, err := state.commitPolicy(req)
				if first.Swap(false) {
					time.Sleep(5 * wPolicyTestTimeout / 4)
				}
				return out, err
			},
		})
		if err := w.SetPolicy(deny); err != nil {
			t.Fatalf("lost commit response: %v", err)
		}
		if state.gen != 1 || w.gen != 1 || live.Allows([4]byte{8, 8, 8, 8}, 6, 443) {
			t.Fatalf("status did not confirm committed generation: worker=%d supervisor=%d", state.gen, w.gen)
		}
		// Let the deliberately late response arrive; Client must drop it and
		// remain usable for the next generation.
		time.Sleep(2 * wPolicyTestTimeout)
		if err := w.SetPolicy(allow); err != nil {
			t.Fatalf("call after late response: %v", err)
		}
		if state.gen != 2 || w.gen != 2 || !live.Allows([4]byte{8, 8, 8, 8}, 6, 443) {
			t.Fatalf("post-timeout transaction did not converge: worker=%d supervisor=%d", state.gen, w.gen)
		}
	})

	t.Run("abort readback recognizes a committed transaction", func(t *testing.T) {
		state, live := newPolicyTransactionState(t)
		var commits atomic.Int32
		var statuses atomic.Int32
		w := startPolicyTransactionRPC(t, state, map[string]workerproto.Handler{
			"policy.commit": func(req workerproto.Request) (any, error) {
				if commits.Add(1) == 1 {
					return nil, errors.New("injected commit rejection")
				}
				out, err := state.commitPolicy(req)
				// Apply the retry but lose its response. The following status
				// failure forces the supervisor to resolve through abort.
				time.Sleep(5 * wPolicyTestTimeout / 4)
				return out, err
			},
			"policy.status": func(req workerproto.Request) (any, error) {
				if statuses.Add(1) == 3 {
					return nil, errors.New("injected status response loss")
				}
				return state.policyStatus(req)
			},
		})
		if err := w.SetPolicy(deny); err != nil {
			t.Fatalf("committed transaction reported failure: %v", err)
		}
		if state.gen != 1 || w.gen != 1 || live.Allows([4]byte{8, 8, 8, 8}, 6, 443) {
			t.Fatalf("abort readback did not recognize commit: worker=%d supervisor=%d", state.gen, w.gen)
		}
	})

	t.Run("failed commits abort and next call reuses generation", func(t *testing.T) {
		state, live := newPolicyTransactionState(t)
		var fail atomic.Bool
		fail.Store(true)
		w := startPolicyTransactionRPC(t, state, map[string]workerproto.Handler{
			"policy.commit": func(req workerproto.Request) (any, error) {
				if fail.Load() {
					return nil, errors.New("injected persistent commit failure")
				}
				return state.commitPolicy(req)
			},
		})
		if err := w.SetPolicy(deny); err == nil {
			t.Fatal("failed commits reported success")
		}
		if state.gen != 0 || state.pending != nil || !live.Allows([4]byte{8, 8, 8, 8}, 6, 443) {
			t.Fatalf("failed commit did not preserve generation zero: gen=%d pending=%v", state.gen, state.pending != nil)
		}
		fail.Store(false)
		if err := w.SetPolicy(deny); err != nil {
			t.Fatalf("retry after aborted commit: %v", err)
		}
		if state.gen != 1 || w.gen != 1 {
			t.Fatalf("retry skipped generation: worker=%d supervisor=%d", state.gen, w.gen)
		}
	})
}

// The transaction tests intentionally cross a client deadline to model a
// lost response. Keep the bound generous enough for the race detector and
// loaded CI; handler delays are derived from it, so the timeout behavior stays
// deterministic rather than depending on a tiny scheduler window.
const wPolicyTestTimeout = 200 * time.Millisecond

// TestNetWorkerHelperProcess IS the worker when re-executed by
// TestNetWorkerReExec (helper-process pattern): it serves on the real
// inherited fds 3/4 and exits 0 on graceful shutdown.
func TestNetWorkerHelperProcess(t *testing.T) {
	if os.Getenv("GANTRY_TEST_NET_WORKER") != "1" {
		return
	}
	control, err := inheritedConn(3, "control")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	data, err := inheritedConn(4, "data")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := runNetWorker(control, data); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

// TestNetWorkerReExec validates the real descriptor-inheritance path:
// the worker runs as a separate OS process (this test binary) with the
// control/data socketpairs as fds 3/4, exactly like production spawn.
func TestNetWorkerReExec(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctrlSup, ctrlWrk, err := socketpairConns()
	if err != nil {
		t.Fatal(err)
	}
	dataSup, dataWrk, err := socketpairConns()
	if err != nil {
		t.Fatal(err)
	}
	ctrlFile, err := connFile(ctrlWrk)
	if err != nil {
		t.Fatal(err)
	}
	dataFile, err := connFile(dataWrk)
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

	nonce := workerproto.NewNonce()
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
	if err := client.Call("port.publish", portPublishRequest{Proto: "tcp", Local: "127.0.0.1:18082", Remote: "192.168.127.2:8082"}, nil); err != nil {
		t.Fatalf("publish over re-exec: %v\n%s", err, outBuf.String())
	}
	if err := client.Call("shutdown", nil, nil); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	_ = ctrlSup.Close()
	_ = dataSup.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("worker exit: %v\n%s", err, outBuf.String())
	}
}

// hookNetWorkerSpawnForTests routes StartNetwork's re-exec through the
// helper-process entry point of this test binary.
func hookNetWorkerSpawnForTests(t *testing.T) {
	t.Helper()
	old := netWorkerSpawnHook
	netWorkerSpawnHook = func(argv *[]string, env *[]string) {
		*argv = []string{(*argv)[0], "-test.run", "^TestNetWorkerHelperProcess$"}
		*env = append(*env, "GANTRY_TEST_NET_WORKER=1")
	}
	t.Cleanup(func() { netWorkerSpawnHook = old })
}

// TestStartNetworkSplitModes exercises StartNetwork's topology decision:
// auto/required split on Unix, off stays monolithic, and the backend is
// functional in both.
func TestStartNetworkSplitModes(t *testing.T) {
	hookNetWorkerSpawnForTests(t)
	for _, tc := range []struct {
		mode string
		want bool
	}{
		{"auto", true},
		{"", true}, // empty behaves as auto (pre-existing configs upgrade)
		{"required", true},
		{"off", false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			cfg := RunConfig{Net: true, ProcessIsolation: tc.mode}
			n, err := cfg.StartNetwork(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close()
			if n.Split != tc.want {
				t.Fatalf("mode %q: split=%v want %v (degraded: %v)", tc.mode, n.Split, tc.want, n.Degraded)
			}
			if n.Backend == nil {
				t.Fatal("no backend")
			}
			if err := n.Backend.Publish("tcp", "127.0.0.1:18083", "192.168.127.2:8083"); err != nil {
				t.Fatal(err)
			}
			fw, err := n.Backend.Forwards()
			if err != nil || len(fw) != 1 {
				t.Fatalf("forwards: %+v err=%v", fw, err)
			}
			if err := n.Backend.Unpublish("tcp", "127.0.0.1:18083"); err != nil {
				t.Fatal(err)
			}
			// split: the worker owns enforcement + the traffic recorder;
			// the supervisor keeps only its display/rollback policy copy,
			// which Opts must NOT attach to the device. (Fake kernel: just
			// enough header for KernelArch's ARM64 magic at 0x38.)
			kernel := filepath.Join(t.TempDir(), "Image")
			hdr := make([]byte, 64)
			copy(hdr[0x38:], "ARMd")
			if err := os.WriteFile(kernel, hdr, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg.Kernel = kernel
			opts, err := cfg.Opts(n, nil, t.TempDir(), false)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want {
				if n.Traffic != nil {
					t.Fatal("split network exposes the traffic recorder to the device")
				}
				if opts.NetPolicy != nil || opts.NetTraffic != nil {
					t.Fatal("Opts attaches worker-owned policy/traffic to the device")
				}
				if opts.NetConn == nil {
					t.Fatal("split network lost the device data channel")
				}
			} else {
				if n.Policy == nil || n.Traffic == nil {
					t.Fatal("monolithic network lost policy/traffic")
				}
				if opts.NetPolicy == nil || opts.NetTraffic == nil {
					t.Fatal("monolithic Opts lost policy/traffic")
				}
			}
		})
	}
}

func TestWriteIsolationStateConfinement(t *testing.T) {
	dir := t.TempDir()
	nw := &Network{}
	conf := &workerconf.Report{
		Platform: "linux", Mode: "auto", Applied: true,
		Results: []workerconf.PropertyResult{
			{Property: workerconf.PropFSRead, State: workerconf.StateEnforced},
			{Property: workerconf.PropNetDial, State: workerconf.StateEnforced},
			{Property: workerconf.PropExec, State: workerconf.StateEnforced},
			{Property: workerconf.PropProcEnum, State: workerconf.StateUnenforced, Detail: "/proc readable"},
			{Property: workerconf.PropFSWrite, State: workerconf.StateUnenforced, Detail: "probe"},
		},
	}
	if err := writeIsolationState(dir, RunConfig{ProcessIsolation: "auto"}, nw, true, conf); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "isolation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st isolationState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	if st.Confinement == nil || !st.Confinement.Applied {
		t.Fatalf("report not persisted: %s", data)
	}
	if st.FilesystemBoundary != "enforced" || st.NetworkBoundary != "enforced" {
		t.Fatalf("boundaries not filled from report: %+v", st)
	}
	if st.ProcessBoundary != workerconf.StateUnenforced {
		t.Fatalf("Linux process boundary ignored proc-enum: %+v", st)
	}
	// The one unenforced property must surface in Degraded.
	found := false
	for _, d := range st.Degraded {
		if strings.Contains(d, workerconf.PropFSWrite) {
			found = true
		}
	}
	if !found {
		t.Fatalf("unenforced property not reported degraded: %v", st.Degraded)
	}
	// Monolithic boot: no report, honest unavailable everywhere.
	if err := writeIsolationState(dir, RunConfig{ProcessIsolation: "auto"}, nw, false, nil); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, "isolation.json"))
	var st2 isolationState
	if err := json.Unmarshal(data, &st2); err != nil {
		t.Fatal(err)
	}
	if st2.Confinement != nil || st2.FilesystemBoundary != "unavailable" {
		t.Fatalf("monolithic state not honestly unavailable: %+v", st2)
	}
}

func TestWriteIsolationStateDarwinAggregatesSignalBoundary(t *testing.T) {
	dir := t.TempDir()
	conf := &workerconf.Report{
		Platform: "darwin", Mode: "auto", Applied: true,
		Results: []workerconf.PropertyResult{
			{Property: workerconf.PropFSRead, State: workerconf.StateEnforced},
			{Property: workerconf.PropFSWrite, State: workerconf.StateEnforced},
			{Property: workerconf.PropNetDial, State: workerconf.StateEnforced},
			{Property: workerconf.PropExec, State: workerconf.StateEnforced},
			{Property: workerconf.PropProcEnum, State: workerconf.StateUnavailable},
			{Property: workerconf.PropProcSignal, State: workerconf.StateUnenforced},
		},
	}
	if err := writeIsolationState(dir, RunConfig{ProcessIsolation: "auto"}, &Network{}, true, conf); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "isolation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state isolationState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	if state.ProcessBoundary != workerconf.StateUnenforced {
		t.Fatalf("Darwin process boundary ignored proc-signal: %+v", state)
	}
}
