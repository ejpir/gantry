package manager

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type runtimeTestOrder struct {
	mu     sync.Mutex
	values []string
}

func (order *runtimeTestOrder) add(value string) {
	order.mu.Lock()
	order.values = append(order.values, value)
	order.mu.Unlock()
}

func (order *runtimeTestOrder) snapshot() []string {
	order.mu.Lock()
	defer order.mu.Unlock()
	return append([]string(nil), order.values...)
}

type runtimeCountCloser struct{ calls atomic.Int32 }

func (closer *runtimeCountCloser) Close() error {
	closer.calls.Add(1)
	return nil
}

type runtimeTestCloser struct {
	name  string
	order *runtimeTestOrder
}

func (closer runtimeTestCloser) Close() error {
	closer.order.add(closer.name)
	return nil
}

type runtimeTestReceiver struct {
	name  string
	order *runtimeTestOrder
}

func (receiver runtimeTestReceiver) Close() { receiver.order.add(receiver.name) }

type runtimeTestListener struct {
	once   sync.Once
	closed chan struct{}
	order  *runtimeTestOrder
}

func newRuntimeTestListener(order *runtimeTestOrder) *runtimeTestListener {
	return &runtimeTestListener{closed: make(chan struct{}), order: order}
}

func (listener *runtimeTestListener) Accept() (net.Conn, error) {
	<-listener.closed
	return nil, net.ErrClosed
}

func (listener *runtimeTestListener) Close() error {
	listener.once.Do(func() {
		listener.order.add("listener")
		close(listener.closed)
	})
	return nil
}

func (*runtimeTestListener) Addr() net.Addr { return runtimeTestAddr("manager-test") }

type runtimeTestAddr string

func (address runtimeTestAddr) Network() string { return "test" }
func (address runtimeTestAddr) String() string  { return string(address) }

func TestManagerLifecycleTransitions(t *testing.T) {
	var lifecycle managerLifecycle
	for _, next := range []managerPhase{managerLocked, managerListening, managerFeedsReady, managerServing, managerStopping, managerStopped} {
		if err := lifecycle.transition(next); err != nil {
			t.Fatalf("transition to %s: %v", next, err)
		}
	}
	if lifecycle.current() != managerStopped {
		t.Fatalf("terminal phase = %s", lifecycle.current())
	}
	if err := lifecycle.transition(managerServing); err == nil {
		t.Fatal("stopped manager returned to serving")
	}
}

func TestManagerLifecycleRejectsInvalidTransitions(t *testing.T) {
	for _, test := range []struct{ from, to managerPhase }{
		{managerNew, managerServing},
		{managerLocked, managerFeedsReady},
		{managerListening, managerServing},
		{managerFeedsReady, managerStopped},
		{managerServing, managerStopped},
		{managerStopped, managerStopping},
	} {
		lifecycle := managerLifecycle{phase: test.from}
		if err := lifecycle.transition(test.to); err == nil {
			t.Errorf("transition %s -> %s succeeded", test.from, test.to)
		}
		if lifecycle.current() != test.from {
			t.Errorf("rejected transition changed phase to %s", lifecycle.current())
		}
	}
}

func TestManagerRuntimeClosesOwnersAfterJoiningBorrowers(t *testing.T) {
	order := &runtimeTestOrder{}
	service := newManagerService(stubLifecycle{})
	owner := newManagerRuntime(service)
	if err := owner.SetLock(runtimeTestCloser{name: "lock", order: order}); err != nil {
		t.Fatal(err)
	}
	listener := newRuntimeTestListener(order)
	if err := owner.AddServer(&http.Server{}, listener, ""); err != nil {
		t.Fatal(err)
	}
	receiver := runtimeTestReceiver{name: "receiver", order: order}
	if err := owner.FeedsReady([]managerReceiver{receiver}); err != nil {
		t.Fatal(err)
	}
	requestDone, ok := service.requests.Acquire()
	if !ok {
		t.Fatal("request borrower was rejected")
	}
	requestReleased := make(chan struct{})
	go func() {
		<-listener.closed
		order.add("request")
		close(requestReleased)
		requestDone()
	}()
	if !service.startBackground(func(ctx context.Context) {
		<-ctx.Done()
		<-listener.closed
		<-requestReleased
		order.add("background")
	}) {
		t.Fatal("background borrower was rejected")
	}
	if err := owner.StartServers(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{"listener", "request", "background", "receiver", "lock"}
	if got := order.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("close order = %v, want %v", got, want)
	}
	if owner.lifecycle.current() != managerStopped {
		t.Fatalf("terminal phase = %s", owner.lifecycle.current())
	}
	if service.startBackground(func(context.Context) {}) {
		t.Fatal("background admission reopened after shutdown")
	}
}

func TestManagerRuntimeConcurrentCloseIsIdempotent(t *testing.T) {
	service := newManagerService(stubLifecycle{})
	owner := newManagerRuntime(service)
	lock := &runtimeCountCloser{}
	if err := owner.SetLock(lock); err != nil {
		t.Fatal(err)
	}
	var callers sync.WaitGroup
	for range 32 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			if err := owner.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
	}
	callers.Wait()
	if got := lock.calls.Load(); got != 1 {
		t.Fatalf("state lock closes = %d, want 1", got)
	}
	if owner.lifecycle.current() != managerStopped {
		t.Fatalf("terminal phase = %s", owner.lifecycle.current())
	}
}

func TestManagerServiceStopRejectsRequestAndOperationAdmission(t *testing.T) {
	service := newManagerService(stubLifecycle{})
	handler := service.ownedHandler(service.handler())
	service.stopAdmission()
	request := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("request after stop status = %d", response.Code)
	}
	if _, err := service.beginOperation("start", "dev", "", "fingerprint"); !errors.Is(err, errManagerStopping) {
		t.Fatalf("operation after stop = %v", err)
	}
}

func TestManagerTaskGroupConcurrentStopRejectsLateAdmission(t *testing.T) {
	var group managerTaskGroup
	entered := make(chan struct{})
	release := make(chan struct{})
	if !group.Start(func() { close(entered); <-release }) {
		t.Fatal("initial task was rejected")
	}
	<-entered
	group.StopAdmission()
	if group.Start(func() {}) {
		t.Fatal("task admitted after stop")
	}
	waited := make(chan struct{})
	go func() { group.Wait(); close(waited) }()
	select {
	case <-waited:
		t.Fatal("Wait returned before the task exited")
	default:
	}
	close(release)
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("Wait did not join the task")
	}
}
