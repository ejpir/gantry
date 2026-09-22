package vmm

import (
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countedConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *countedConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

type closeCapableHotMemoryMapper struct{}

func (*closeCapableHotMemoryMapper) Close() error        { return nil }
func (*closeCapableHotMemoryMapper) mapHotMemory() error { return nil }

func TestWHPXBrokerOwnerClosesTransportOnce(t *testing.T) {
	ownerSide, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	conn := &countedConn{Conn: ownerSide}
	resources := machineResources{whpxBroker: conn}

	var callers sync.WaitGroup
	for range 16 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			_ = resources.closeWHPXBroker()
		}()
	}
	callers.Wait()
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("broker transport closes = %d, want 1", got)
	}
}

func TestMachineCloseCancelsUnadoptedWHPXBrokerStartup(t *testing.T) {
	ownerSide, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	conn := &countedConn{Conn: ownerSide}
	m := &Machine{machineResources: machineResources{whpxBroker: conn}}
	if err := m.beginRun(); err != nil {
		t.Fatal(err)
	}
	borrow, _, err := m.borrowWHPXBroker()
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		var one [1]byte
		_, err := borrow.Read(one[:])
		readDone <- err
	}()
	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("broker read unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel broker startup I/O")
	}
	if err := m.finishRun(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join startup")
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("broker transport closes = %d, want 1", got)
	}
}

func TestPrepareFailureClosesWHPXBrokerTransport(t *testing.T) {
	ownerSide, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	conn := &countedConn{Conn: ownerSide}
	if _, err := Prepare(Opts{WHPXBroker: conn}); err == nil {
		t.Fatal("Prepare unexpectedly accepted missing boot resources")
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("broker transport closes = %d, want 1", got)
	}
}

func TestPrepareRejectsReusedNetworkTransportAndClosesItOnce(t *testing.T) {
	ownerSide, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	conn := &countedConn{Conn: ownerSide}
	if _, err := Prepare(Opts{NetConn: conn, WHPXBroker: conn}); err == nil {
		t.Fatal("Prepare unexpectedly accepted a reused transport")
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("reused transport closes = %d, want 1", got)
	}
}

func TestBorrowedRuntimeCapabilitiesOmitClose(t *testing.T) {
	for name, borrow := range map[string]reflect.Type{
		"WHPX transport":    reflect.TypeOf((*whpxBrokerBorrow)(nil)).Elem(),
		"hot-memory mapper": reflect.TypeOf((*hotMemoryMapper)(nil)).Elem(),
	} {
		if _, exists := borrow.MethodByName("Close"); exists {
			t.Errorf("borrowed %s exposes Close", name)
		}
	}

	ownerSide, peer := net.Pipe()
	defer func() { _ = ownerSide.Close(); _ = peer.Close() }()
	m := &Machine{machineResources: machineResources{whpxBroker: ownerSide}}
	if err := m.beginRun(); err != nil {
		t.Fatal(err)
	}
	transport, _, err := m.borrowWHPXBroker()
	if err != nil {
		t.Fatal(err)
	}
	if _, closable := any(transport).(interface{ Close() error }); closable {
		t.Fatal("borrowed WHPX transport dynamically exposes Close")
	}

	var backend machineBackendOwner
	if err := backend.adopt(&closeCapableHotMemoryMapper{}); err != nil {
		t.Fatal(err)
	}
	mapper, ok := backend.hotMemoryMapper()
	if !ok {
		t.Fatal("hot-memory mapper capability was not exposed")
	}
	if _, closable := any(mapper).(interface{ Close() error }); closable {
		t.Fatal("borrowed hot-memory mapper dynamically exposes Close")
	}
}
