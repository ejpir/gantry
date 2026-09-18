package sandbox

import (
	"context"
	"net"
	"reflect"
	"sync"
	"testing"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/sandbox/vmmworker"
	"github.com/ejpir/gantry/internal/sharefs"
)

type orderedListener struct {
	once   sync.Once
	record func(string)
	closed chan struct{}
}

func newOrderedListener(record func(string)) *orderedListener {
	return &orderedListener{record: record, closed: make(chan struct{})}
}

func (l *orderedListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}
func (l *orderedListener) Close() error {
	l.once.Do(func() {
		l.record("control")
		close(l.closed)
	})
	return nil
}
func (*orderedListener) Addr() net.Addr { return orderedAddr("control") }

type orderedAddr string

func (a orderedAddr) Network() string { return string(a) }
func (a orderedAddr) String() string  { return string(a) }

func TestDaemonSupervisorClosesOwnersInReverseAcquisitionOrder(t *testing.T) {
	var mu sync.Mutex
	var order []string
	record := func(value string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, value)
	}

	runnerDone := make(chan struct{})
	runner := &closeFailureRunner{done: runnerDone, onClose: func() error {
		record("guest")
		close(runnerDone)
		return nil
	}}
	d := &daemonSupervisor{
		host:  hostPlane{network: &Network{close: func() error { record("host"); return nil }}},
		guest: guestPlane{runner: runner},
	}
	d.control.listener = newOrderedListener(record)
	if !d.background.start(func(ctx context.Context) {
		<-ctx.Done()
		record("background")
	}) {
		t.Fatal("background task was rejected")
	}
	d.guest.start()

	d.close()
	d.close()

	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()
	want := []string{"background", "control", "guest", "host"}
	if len(got) != len(want) {
		t.Fatalf("close order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("close order = %v, want %v", got, want)
		}
	}
	if runner.calls != 1 {
		t.Fatalf("runner Close calls = %d, want 1", runner.calls)
	}
}

func TestBorrowedCapabilitiesDoNotExposeClose(t *testing.T) {
	interfaces := []reflect.Type{
		reflect.TypeOf((*configStoreBorrow)(nil)).Elem(),
		reflect.TypeOf((*networkBorrow)(nil)).Elem(),
		reflect.TypeOf((*networkWorkerBorrow)(nil)).Elem(),
		reflect.TypeOf((*shareManagerBorrow)(nil)).Elem(),
		reflect.TypeOf((*portManagerBorrow)(nil)).Elem(),
		reflect.TypeOf((*guestRunnerBorrow)(nil)).Elem(),
		reflect.TypeOf((*guestRPCBorrow)(nil)).Elem(),
		reflect.TypeOf((*control.VMMPolicyPusher)(nil)).Elem(),
		reflect.TypeOf((*vmmworker.ShareProvider)(nil)).Elem(),
		reflect.TypeOf((*vmmworker.NetAttachment)(nil)).Elem(),
		reflect.TypeOf((*sharefs.BorrowedHub)(nil)).Elem(),
	}
	for _, capability := range interfaces {
		if _, ok := capability.MethodByName("Close"); ok {
			t.Fatalf("borrowed interface %s exposes Close", capability)
		}
	}

	runner := &closeFailureRunner{done: make(chan struct{})}
	guest := guestPlane{runner: runner}
	borrowed := []any{
		guest.runnerBorrow(),
		guestRPCClient{},
		guestPolicyPusherView{pusher: policyPusherStub{}},
		guestPacketCaptureView{},
		networkView{},
		shareManagerView{},
	}
	for _, capability := range borrowed {
		if _, ok := capability.(interface{ Close() error }); ok {
			t.Fatalf("borrowed capability %T exposes Close", capability)
		}
	}
}

type policyPusherStub struct{}

func (policyPusherStub) SetPolicy(*netpol.Policy) error { return nil }
