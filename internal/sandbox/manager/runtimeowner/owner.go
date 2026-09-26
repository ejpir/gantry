package runtimeowner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type Phase uint8

const (
	NewPhase Phase = iota
	Locked
	Listening
	FeedsReadyPhase
	Serving
	Stopping
	Stopped
	Failed
)

func (phase Phase) String() string {
	switch phase {
	case NewPhase:
		return "new"
	case Locked:
		return "locked"
	case Listening:
		return "listening"
	case FeedsReadyPhase:
		return "feeds-ready"
	case Serving:
		return "serving"
	case Stopping:
		return "stopping"
	case Stopped:
		return "stopped"
	case Failed:
		return "failed"
	default:
		return fmt.Sprintf("Phase(%d)", uint8(phase))
	}
}

type Lifecycle struct {
	mu    sync.Mutex
	phase Phase
}

func (lifecycle *Lifecycle) transition(next Phase) error {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	valid := false
	switch lifecycle.phase {
	case NewPhase:
		valid = next == Locked || next == Stopping || next == Failed
	case Locked:
		valid = next == Listening || next == Stopping || next == Failed
	case Listening:
		valid = next == FeedsReadyPhase || next == Stopping || next == Failed
	case FeedsReadyPhase:
		valid = next == Serving || next == Stopping || next == Failed
	case Serving:
		valid = next == Stopping || next == Failed
	case Stopping:
		valid = next == Stopped || next == Failed
	case Failed:
		valid = next == Stopping || next == Stopped
	}
	if !valid {
		return fmt.Errorf("invalid manager transition %s -> %s", lifecycle.phase, next)
	}
	lifecycle.phase = next
	return nil
}

func (lifecycle *Lifecycle) beginStop() {
	lifecycle.mu.Lock()
	if lifecycle.phase != Stopped && lifecycle.phase != Stopping {
		lifecycle.phase = Stopping
	}
	lifecycle.mu.Unlock()
}

func (lifecycle *Lifecycle) Current() Phase {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return lifecycle.phase
}

// TaskGroup serializes background admission with shutdown. The service
// owns cancellation; the group guarantees Wait cannot race Add.
type TaskGroup struct {
	mu      sync.Mutex
	stopped bool
	workers sync.WaitGroup
}

func (group *TaskGroup) Acquire() (func(), bool) {
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.stopped {
		return nil, false
	}
	group.workers.Add(1)
	return group.workers.Done, true
}

func (group *TaskGroup) Start(run func()) bool {
	if run == nil {
		return false
	}
	done, ok := group.Acquire()
	if !ok {
		return false
	}
	go func() {
		defer done()
		run()
	}()
	return true
}

func (group *TaskGroup) StopAdmission() {
	group.mu.Lock()
	group.stopped = true
	group.mu.Unlock()
}

func (group *TaskGroup) Wait() { group.workers.Wait() }

type Receiver interface {
	Close()
}

type managedServer struct {
	server   *http.Server
	listener net.Listener
	endpoint string
}

type Hooks struct {
	StopAdmission  func()
	JoinRequests   func()
	JoinBackground func()
}

// Owner owns process-level manager resources. Service request state is
// separate, but runtime shutdown closes its admission before releasing servers,
// receivers, listener paths, and finally the state lock.
type Owner struct {
	lifecycle     Lifecycle
	admissionMu   sync.Mutex
	hooks         Hooks
	shutdownGrace time.Duration

	lock      io.Closer
	servers   []managedServer
	receivers []Receiver

	serveErrors chan error
	serversWG   sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error
}

func New(hooks Hooks, shutdownGrace time.Duration) *Owner {
	if shutdownGrace <= 0 {
		panic("runtimeowner: shutdown grace period must be positive")
	}
	return &Owner{hooks: hooks, shutdownGrace: shutdownGrace}
}

func (runtime *Owner) Phase() Phase { return runtime.lifecycle.Current() }

func (runtime *Owner) SetLock(lock io.Closer) error {
	runtime.admissionMu.Lock()
	defer runtime.admissionMu.Unlock()
	if lock == nil {
		return errors.New("manager state lock is nil")
	}
	if err := runtime.lifecycle.transition(Locked); err != nil {
		return err
	}
	runtime.lock = lock
	return nil
}

func (runtime *Owner) AddServer(server *http.Server, listener net.Listener, endpoint string) error {
	runtime.admissionMu.Lock()
	defer runtime.admissionMu.Unlock()
	if server == nil || listener == nil {
		return errors.New("manager server and listener are required")
	}
	if phase := runtime.lifecycle.Current(); phase != Locked && phase != Listening {
		return fmt.Errorf("add manager server in phase %s", phase)
	}
	runtime.servers = append(runtime.servers, managedServer{server: server, listener: listener, endpoint: endpoint})
	if runtime.lifecycle.Current() == Locked {
		return runtime.lifecycle.transition(Listening)
	}
	return nil
}

func (runtime *Owner) FeedsReady(receivers []Receiver) error {
	runtime.admissionMu.Lock()
	defer runtime.admissionMu.Unlock()
	if runtime.lifecycle.Current() != Listening {
		return fmt.Errorf("publish manager feeds in phase %s", runtime.lifecycle.Current())
	}
	runtime.receivers = append(runtime.receivers, receivers...)
	return runtime.lifecycle.transition(FeedsReadyPhase)
}

// AttachReceiver transfers a verified live feed to runtime ownership while
// the servers are running. Close serializes with this handoff and releases it
// only after all background tasks have joined.
func (runtime *Owner) AttachReceiver(receiver Receiver) error {
	runtime.admissionMu.Lock()
	defer runtime.admissionMu.Unlock()
	if receiver == nil || runtime.lifecycle.Current() != Serving {
		return fmt.Errorf("attach policy receiver in phase %s", runtime.lifecycle.Current())
	}
	runtime.receivers = append(runtime.receivers, receiver)
	return nil
}

func (runtime *Owner) StartServers() error {
	runtime.admissionMu.Lock()
	defer runtime.admissionMu.Unlock()
	if err := runtime.lifecycle.transition(Serving); err != nil {
		return err
	}
	runtime.serveErrors = make(chan error, len(runtime.servers))
	for _, managed := range runtime.servers {
		runtime.serversWG.Add(1)
		go func(server *http.Server, listener net.Listener) {
			defer runtime.serversWG.Done()
			if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
				runtime.serveErrors <- err
			}
		}(managed.server, managed.listener)
	}
	return nil
}

func (runtime *Owner) ServeErrors() <-chan error { return runtime.serveErrors }

func (runtime *Owner) Close() error {
	runtime.closeOnce.Do(func() {
		runtime.admissionMu.Lock()
		runtime.lifecycle.beginStop()
		if runtime.hooks.StopAdmission != nil {
			runtime.hooks.StopAdmission()
		}
		runtime.admissionMu.Unlock()

		var errs []error
		shutdownCtx, cancel := context.WithTimeout(context.Background(), runtime.shutdownGrace)
		for index := len(runtime.servers) - 1; index >= 0; index-- {
			managed := runtime.servers[index]
			if err := managed.server.Shutdown(shutdownCtx); err != nil {
				errs = append(errs, err)
				_ = managed.server.Close()
			}
			_ = managed.listener.Close()
		}
		cancel()
		runtime.serversWG.Wait()
		if runtime.hooks.JoinRequests != nil {
			runtime.hooks.JoinRequests()
		}
		if runtime.hooks.JoinBackground != nil {
			runtime.hooks.JoinBackground()
		}
		for index := len(runtime.receivers) - 1; index >= 0; index-- {
			runtime.receivers[index].Close()
		}
		for index := len(runtime.servers) - 1; index >= 0; index-- {
			if endpoint := runtime.servers[index].endpoint; endpoint != "" {
				if err := os.Remove(endpoint); err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, fmt.Errorf("remove manager endpoint: %w", err))
				}
			}
		}
		if runtime.lock != nil {
			errs = append(errs, runtime.lock.Close())
			runtime.lock = nil
		}
		runtime.closeErr = errors.Join(errs...)
		if runtime.closeErr != nil {
			_ = runtime.lifecycle.transition(Failed)
		} else {
			_ = runtime.lifecycle.transition(Stopped)
		}
	})
	return runtime.closeErr
}
