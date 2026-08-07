//go:build linux || darwin

package workerproto

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func unixPair(t *testing.T) (a, b net.Conn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	// index 0 is the supervisor end, 1 the worker end; FileConn dups
	// the descriptor, so the wrappers must close or EOF never
	// propagates when a conn closes
	fa := os.NewFile(uintptr(fds[0]), "sup")
	fb := os.NewFile(uintptr(fds[1]), "wrk")
	ca, err := net.FileConn(fa)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := net.FileConn(fb)
	if err != nil {
		t.Fatal(err)
	}
	_ = fa.Close()
	_ = fb.Close()
	return ca, cb
}

// TestSendRecvFD transfers a live descriptor: reading through the
// received copy returns exactly what the sender wrote, and the token
// correlates the transfer.
func TestSendRecvFD(t *testing.T) {
	a, b := unixPair(t)
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()

	f, err := os.CreateTemp(t.TempDir(), "fd-pass-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString("descriptor-payload"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}

	var token [FDTokenLen]byte
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	type result struct {
		tok [FDTokenLen]byte
		f   *os.File
		err error
	}
	got := make(chan result, 1)
	go func() {
		tok, rf, err := RecvFD(b)
		got <- result{tok, rf, err}
	}()
	if err := SendFD(a, token, f); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-got:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.tok != token {
			t.Fatal("token mismatch")
		}
		defer func() { _ = r.f.Close() }()
		buf := make([]byte, 64)
		n, err := r.f.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != "descriptor-payload" {
			t.Fatalf("received descriptor read %q", buf[:n])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RecvFD did not return")
	}
}

// TestRecvFDTimeout: with nothing sent, RecvFD fails instead of hanging.
func TestRecvFDTimeout(t *testing.T) {
	a, b := unixPair(t)
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	done := make(chan struct{})
	go func() {
		_, _, err := RecvFD(b)
		if err == nil {
			t.Error("RecvFD with no sender succeeded")
		}
		close(done)
	}()
	_ = a.Close() // peer EOF must also unwind the receive
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RecvFD hung after peer close")
	}
}

// TestConcurrentCallsParkedWait: a parked long call must not starve
// short calls, and responses match their requests even when the worker
// answers out of order.
func TestConcurrentCallsParkedWait(t *testing.T) {
	cSup, cWrk := net.Pipe()
	defer func() { _ = cSup.Close() }()
	release := make(chan struct{})
	srvErr := make(chan error, 1)
	go func() {
		srvErr <- ServeRequests(cWrk, map[string]Handler{
			"wait": func(req Request) (any, error) {
				<-release
				return "released", nil
			},
			"echo": func(req Request) (any, error) {
				var v string
				if err := json.Unmarshal(req.Body, &v); err != nil {
					return nil, err
				}
				return v, nil
			},
		})
	}()

	client := NewClient(cSup)
	defer func() { _ = client.Close() }()

	waitOut := make(chan error, 1)
	go func() {
		var out string
		err := client.Call("wait", nil, &out)
		if err == nil && out != "released" {
			err = fmt.Errorf("wait returned %q", out)
		}
		waitOut <- err
	}()

	// While wait is parked, echo calls must round-trip.
	for i := 0; i < 8; i++ {
		var out string
		want := fmt.Sprintf("ping-%d", i)
		if err := client.Call("echo", want, &out); err != nil {
			t.Fatal(err)
		}
		if out != want {
			t.Fatalf("echo = %q, want %q", out, want)
		}
	}
	close(release)
	select {
	case err := <-waitOut:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parked wait never returned")
	}
	_ = client.Close()
	if err := <-srvErr; err != nil {
		t.Fatalf("serve loop: %v", err)
	}
}

// TestConcurrentCallsParallel exercises many simultaneous callers with
// deliberately slow handlers: responses must still match by ID.
func TestConcurrentCallsParallel(t *testing.T) {
	cSup, cWrk := net.Pipe()
	defer func() { _ = cSup.Close() }()
	go func() {
		_ = ServeRequests(cWrk, map[string]Handler{
			"slow-double": func(req Request) (any, error) {
				var n int
				if err := json.Unmarshal(req.Body, &n); err != nil {
					return nil, err
				}
				time.Sleep(time.Duration(n%7) * time.Millisecond) // scramble completion order
				return 2 * n, nil
			},
		})
	}()
	client := NewClient(cSup)
	defer func() { _ = client.Close() }()

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			var out int
			if err := client.Call("slow-double", n, &out); err != nil {
				errs <- err
				return
			}
			if out != 2*n {
				errs <- fmt.Errorf("call %d got %d", n, out)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// TestCallTimeoutKeepsChannel: a timed-out call abandons only itself;
// the channel and later calls stay healthy, and the late response is
// dropped without killing the read loop.
func TestCallTimeoutKeepsChannel(t *testing.T) {
	cSup, cWrk := net.Pipe()
	defer func() { _ = cSup.Close() }()
	go func() {
		_ = ServeRequests(cWrk, map[string]Handler{
			"hang": func(req Request) (any, error) {
				time.Sleep(300 * time.Millisecond)
				return "late", nil
			},
			"fast": func(req Request) (any, error) { return "quick", nil },
		})
	}()
	client := NewClient(cSup)
	client.Timeout = 100 * time.Millisecond
	defer func() { _ = client.Close() }()

	if err := client.Call("hang", nil, nil); err == nil {
		t.Fatal("hang call did not time out")
	}
	var out string
	if err := client.Call("fast", nil, &out); err != nil || out != "quick" {
		t.Fatalf("post-timeout call: %v %q", err, out)
	}
	// Let the late "hang" response arrive and be dropped, then the
	// channel must still work.
	time.Sleep(400 * time.Millisecond)
	if err := client.Call("fast", nil, &out); err != nil || out != "quick" {
		t.Fatalf("after late response: %v %q", err, out)
	}
}

// TestClientCloseFailsCalls: closing the conn fails outstanding calls
// rather than hanging them.
func TestClientCloseFailsCalls(t *testing.T) {
	cSup, cWrk := net.Pipe()
	defer func() { _ = cWrk.Close() }()
	go func() {
		_ = ServeRequests(cWrk, map[string]Handler{
			"hang": func(req Request) (any, error) {
				select {} // never answers
			},
		})
	}()
	client := NewClient(cSup)
	client.Timeout = 30 * time.Second
	done := make(chan error, 1)
	go func() { done <- client.Call("hang", nil, nil) }()
	time.Sleep(50 * time.Millisecond)
	_ = client.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("call on closed channel succeeded")
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("call reported timeout instead of channel death")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close did not unwind the parked call")
	}
}

// TestSendFDNonUnixRefused: FD passing on a non-unix conn fails fast.
func TestSendFDNonUnixRefused(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	f, err := os.CreateTemp(t.TempDir(), "fd-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var token [FDTokenLen]byte
	if err := SendFD(a, token, f); err == nil {
		t.Fatal("SendFD over net.Pipe succeeded")
	}
	if _, _, err := RecvFD(b); err == nil {
		t.Fatal("RecvFD over net.Pipe succeeded")
	}
}

// TestFDMuxSurvivesIdleChannel is the regression test for the macOS
// field failure "share.prepare: recv fd: i/o timeout" minutes after
// boot: the mux loop idled on a DEADLINED read and died with a sticky
// error. The loop must block indefinitely; transfers long after boot
// must work.
func TestFDMuxSurvivesIdleChannel(t *testing.T) {
	a, b := unixPair(t)
	mux := NewFDMux(b)
	// No mux close: the loop dies with the conn (unixPair cleanup).

	// Idle longer than fdRecvTimeout: the loop must still be alive.
	time.Sleep(fdRecvTimeout + 2*time.Second)

	f, err := os.CreateTemp(t.TempDir(), "fd-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var token [FDTokenLen]byte
	token[0] = 0x77
	if err := SendFD(a, token, f); err != nil {
		t.Fatal(err)
	}
	ch, err := mux.Expect(token)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-ch:
		if res.Err != nil {
			t.Fatalf("recv after idle: %v", res.Err)
		}
		_ = res.F.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("no dispatch after idle period")
	}
}
