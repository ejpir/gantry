package mcpgw

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/workerconf"
)

type fakeOwnerWorker struct {
	done         chan struct{}
	closeOnce    sync.Once
	serveStarted chan struct{}
	serveExited  chan struct{}
	closed       atomic.Int32
	sessions     atomic.Int32
}

func newFakeOwnerWorker() *fakeOwnerWorker {
	return &fakeOwnerWorker{
		done: make(chan struct{}), serveStarted: make(chan struct{}), serveExited: make(chan struct{}),
	}
}

func (w *fakeOwnerWorker) Serve(_ context.Context, conn net.Conn) error {
	close(w.serveStarted)
	<-w.done
	_ = conn.Close()
	close(w.serveExited)
	return nil
}
func (w *fakeOwnerWorker) Done() <-chan struct{} { return w.done }
func (*fakeOwnerWorker) ConfinementReport() *workerconf.Report {
	return &workerconf.Report{Applied: true}
}
func (w *fakeOwnerWorker) CloseSessions() { w.sessions.Add(1) }
func (w *fakeOwnerWorker) Close() error {
	w.closed.Add(1)
	w.closeOnce.Do(func() { close(w.done) })
	return nil
}

func TestOwnerClosesAndJoinsBorrowers(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	worker := newFakeOwnerWorker()
	workerExited := make(chan struct{})
	var owner Owner
	if !owner.Start(listener, worker, nil, func() { close(workerExited) }) {
		t.Fatal("owner rejected its first worker")
	}
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	select {
	case <-worker.serveStarted:
	case <-time.After(time.Second):
		t.Fatal("accepted connection did not reach worker")
	}
	if report, ok := owner.ConfinementReport(); !ok || report == nil || !report.Applied {
		t.Fatalf("live confinement report = %+v, %t", report, ok)
	}
	owner.CloseSessions()
	if got := worker.sessions.Load(); got != 1 {
		t.Fatalf("CloseSessions calls = %d, want 1", got)
	}

	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	for label, done := range map[string]<-chan struct{}{"session": worker.serveExited, "watcher": workerExited} {
		select {
		case <-done:
		default:
			t.Fatalf("Close returned before %s callback exited", label)
		}
	}
	if got := worker.closed.Load(); got != 1 {
		t.Fatalf("worker Close calls = %d, want 1", got)
	}
	if report, ok := owner.ConfinementReport(); ok || report != nil {
		t.Fatalf("closed confinement report = %+v, %t", report, ok)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestOwnerRejectsSecondWorker(t *testing.T) {
	firstListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	secondListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = secondListener.Close() }()

	firstWorker := newFakeOwnerWorker()
	secondWorker := newFakeOwnerWorker()
	var owner Owner
	if !owner.Start(firstListener, firstWorker, nil, nil) {
		t.Fatal("owner rejected first worker")
	}
	if owner.Start(secondListener, secondWorker, nil, nil) {
		t.Fatal("owner accepted a second live worker")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if got := secondWorker.closed.Load(); got != 0 {
		t.Fatalf("rejected worker ownership changed: Close calls = %d", got)
	}
}
