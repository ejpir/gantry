package controlplane

import (
	"context"
	"net"
	"sync"
	"testing"
)

type testListener struct {
	once    sync.Once
	closed  chan struct{}
	onClose func()
}

func (l *testListener) Accept() (net.Conn, error) { <-l.closed; return nil, net.ErrClosed }
func (l *testListener) Close() error {
	l.once.Do(func() {
		if l.onClose != nil {
			l.onClose()
		}
		close(l.closed)
	})
	return nil
}
func (*testListener) Addr() net.Addr { return testAddr("control") }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }

func TestPlaneClosesOAuthBeforeAdmissionAndJoinsServers(t *testing.T) {
	var mu sync.Mutex
	var order []string
	record := func(value string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, value)
	}
	listener := &testListener{closed: make(chan struct{}), onClose: func() { record("listener") }}
	var plane Plane[struct{}]
	plane.SetListener(listener)
	if !plane.StartOAuth(func(ctx context.Context) { <-ctx.Done(); record("oauth") }) {
		t.Fatal("OAuth task rejected")
	}
	serverExited := make(chan struct{})
	if !plane.StartServer(func(ctx context.Context) { <-ctx.Done(); close(serverExited) }) {
		t.Fatal("server task rejected")
	}

	if err := plane.Close(); err != nil {
		t.Fatal(err)
	}
	if err := plane.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-serverExited:
	default:
		t.Fatal("Close returned before server task exited")
	}
	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()
	if len(got) != 2 || got[0] != "oauth" || got[1] != "listener" {
		t.Fatalf("close order = %v, want [oauth listener]", got)
	}
}
