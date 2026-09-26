package runtimeowner

import (
	"context"
	"net"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testOrder struct {
	mu     sync.Mutex
	values []string
}

func (order *testOrder) add(value string) {
	order.mu.Lock()
	order.values = append(order.values, value)
	order.mu.Unlock()
}

func (order *testOrder) snapshot() []string {
	order.mu.Lock()
	defer order.mu.Unlock()
	return append([]string(nil), order.values...)
}

type countCloser struct{ calls atomic.Int32 }

func (closer *countCloser) Close() error { closer.calls.Add(1); return nil }

type testCloser struct {
	name  string
	order *testOrder
}

func (closer testCloser) Close() error { closer.order.add(closer.name); return nil }

type testReceiver struct {
	name  string
	order *testOrder
}

func (receiver testReceiver) Close() { receiver.order.add(receiver.name) }

type testListener struct {
	once   sync.Once
	closed chan struct{}
	order  *testOrder
}

func newTestListener(order *testOrder) *testListener {
	return &testListener{closed: make(chan struct{}), order: order}
}

func (listener *testListener) Accept() (net.Conn, error) {
	<-listener.closed
	return nil, net.ErrClosed
}
func (listener *testListener) Close() error {
	listener.once.Do(func() { listener.order.add("listener"); close(listener.closed) })
	return nil
}
func (*testListener) Addr() net.Addr { return testAddr("manager-test") }

type testAddr string

func (address testAddr) Network() string { return "test" }
func (address testAddr) String() string  { return string(address) }

func TestLifecycleTransitions(t *testing.T) {
	var lifecycle Lifecycle
	for _, next := range []Phase{Locked, Listening, FeedsReadyPhase, Serving, Stopping, Stopped} {
		if err := lifecycle.transition(next); err != nil {
			t.Fatalf("transition to %s: %v", next, err)
		}
	}
	if lifecycle.Current() != Stopped {
		t.Fatalf("terminal phase = %s", lifecycle.Current())
	}
	if err := lifecycle.transition(Serving); err == nil {
		t.Fatal("stopped manager returned to serving")
	}
}

func TestLifecycleRejectsInvalidTransitions(t *testing.T) {
	for _, test := range []struct{ from, to Phase }{
		{NewPhase, Serving}, {Locked, FeedsReadyPhase}, {Listening, Serving},
		{FeedsReadyPhase, Stopped}, {Serving, Stopped}, {Stopped, Stopping},
	} {
		lifecycle := Lifecycle{phase: test.from}
		if err := lifecycle.transition(test.to); err == nil {
			t.Errorf("transition %s -> %s succeeded", test.from, test.to)
		}
		if lifecycle.Current() != test.from {
			t.Errorf("rejected transition changed phase to %s", lifecycle.Current())
		}
	}
}

func TestOwnerClosesResourcesAfterJoiningBorrowers(t *testing.T) {
	order := &testOrder{}
	ctx, cancel := context.WithCancel(context.Background())
	var requests, background TaskGroup
	owner := New(Hooks{
		StopAdmission: func() { requests.StopAdmission(); background.StopAdmission(); cancel() },
		JoinRequests:  requests.Wait, JoinBackground: background.Wait,
	}, time.Second)
	if err := owner.SetLock(testCloser{name: "lock", order: order}); err != nil {
		t.Fatal(err)
	}
	listener := newTestListener(order)
	if err := owner.AddServer(&http.Server{}, listener, ""); err != nil {
		t.Fatal(err)
	}
	receiver := testReceiver{name: "receiver", order: order}
	if err := owner.FeedsReady([]Receiver{receiver}); err != nil {
		t.Fatal(err)
	}
	requestDone, ok := requests.Acquire()
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
	if !background.Start(func() {
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
	if owner.Phase() != Stopped {
		t.Fatalf("terminal phase = %s", owner.Phase())
	}
	if background.Start(func() {}) {
		t.Fatal("background admission reopened after shutdown")
	}
}

func TestOwnerAttachesLiveReceiverAndClosesItAfterBackground(t *testing.T) {
	order := &testOrder{}
	ctx, cancel := context.WithCancel(context.Background())
	var background TaskGroup
	owner := New(Hooks{
		StopAdmission:  func() { background.StopAdmission(); cancel() },
		JoinBackground: background.Wait,
	}, time.Second)
	if err := owner.SetLock(testCloser{name: "lock", order: order}); err != nil {
		t.Fatal(err)
	}
	if err := owner.AddServer(&http.Server{}, newTestListener(order), ""); err != nil {
		t.Fatal(err)
	}
	if err := owner.FeedsReady(nil); err != nil {
		t.Fatal(err)
	}
	if err := owner.StartServers(); err != nil {
		t.Fatal(err)
	}
	if err := owner.AttachReceiver(testReceiver{name: "live receiver", order: order}); err != nil {
		t.Fatal(err)
	}
	if !background.Start(func() { <-ctx.Done(); order.add("background") }) {
		t.Fatal("background borrower refused")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := order.snapshot(), []string{"listener", "background", "live receiver", "lock"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("close order = %v, want %v", got, want)
	}
	if err := owner.AttachReceiver(testReceiver{name: "late", order: order}); err == nil {
		t.Fatal("receiver attached after shutdown")
	}
}

func TestOwnerConcurrentCloseIsIdempotent(t *testing.T) {
	owner := New(Hooks{}, time.Second)
	lock := &countCloser{}
	if err := owner.SetLock(lock); err != nil {
		t.Fatal(err)
	}
	var callers sync.WaitGroup
	for range 32 {
		callers.Add(1)
		go func() { defer callers.Done(); _ = owner.Close() }()
	}
	callers.Wait()
	if got := lock.calls.Load(); got != 1 {
		t.Fatalf("state lock closes = %d, want 1", got)
	}
	if owner.Phase() != Stopped {
		t.Fatalf("terminal phase = %s", owner.Phase())
	}
}

func TestTaskGroupConcurrentStopRejectsLateAdmission(t *testing.T) {
	var group TaskGroup
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
