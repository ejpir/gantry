package manager

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
)

type managerPhase uint8

const (
	managerNew managerPhase = iota
	managerLocked
	managerListening
	managerFeedsReady
	managerServing
	managerStopping
	managerStopped
	managerFailed
)

func (phase managerPhase) String() string {
	switch phase {
	case managerNew:
		return "new"
	case managerLocked:
		return "locked"
	case managerListening:
		return "listening"
	case managerFeedsReady:
		return "feeds-ready"
	case managerServing:
		return "serving"
	case managerStopping:
		return "stopping"
	case managerStopped:
		return "stopped"
	case managerFailed:
		return "failed"
	default:
		return fmt.Sprintf("managerPhase(%d)", uint8(phase))
	}
}

type managerLifecycle struct {
	mu    sync.Mutex
	phase managerPhase
}

func (lifecycle *managerLifecycle) transition(next managerPhase) error {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	valid := false
	switch lifecycle.phase {
	case managerNew:
		valid = next == managerLocked || next == managerStopping || next == managerFailed
	case managerLocked:
		valid = next == managerListening || next == managerStopping || next == managerFailed
	case managerListening:
		valid = next == managerFeedsReady || next == managerStopping || next == managerFailed
	case managerFeedsReady:
		valid = next == managerServing || next == managerStopping || next == managerFailed
	case managerServing:
		valid = next == managerStopping || next == managerFailed
	case managerStopping:
		valid = next == managerStopped || next == managerFailed
	case managerFailed:
		valid = next == managerStopping || next == managerStopped
	}
	if !valid {
		return fmt.Errorf("invalid manager transition %s -> %s", lifecycle.phase, next)
	}
	lifecycle.phase = next
	return nil
}

func (lifecycle *managerLifecycle) beginStop() {
	lifecycle.mu.Lock()
	if lifecycle.phase != managerStopped && lifecycle.phase != managerStopping {
		lifecycle.phase = managerStopping
	}
	lifecycle.mu.Unlock()
}

func (lifecycle *managerLifecycle) current() managerPhase {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return lifecycle.phase
}

// managerTaskGroup serializes background admission with shutdown. The service
// owns cancellation; the group guarantees Wait cannot race Add.
type managerTaskGroup struct {
	mu      sync.Mutex
	stopped bool
	workers sync.WaitGroup
}

func (group *managerTaskGroup) Acquire() (func(), bool) {
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.stopped {
		return nil, false
	}
	group.workers.Add(1)
	return group.workers.Done, true
}

func (group *managerTaskGroup) Start(run func()) bool {
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

func (group *managerTaskGroup) StopAdmission() {
	group.mu.Lock()
	group.stopped = true
	group.mu.Unlock()
}

func (group *managerTaskGroup) Wait() { group.workers.Wait() }

type managerReceiver interface {
	Close()
}

type managedServer struct {
	server   *http.Server
	listener net.Listener
	endpoint string
}

// managerRuntime owns process-level manager resources. Service request state is
// separate, but runtime shutdown closes its admission before releasing servers,
// receivers, listener paths, and finally the state lock.
type managerRuntime struct {
	lifecycle   managerLifecycle
	admissionMu sync.Mutex
	service     *managerService

	lock      io.Closer
	servers   []managedServer
	receivers []managerReceiver

	serveErrors chan error
	serversWG   sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error
}

func newManagerRuntime(service *managerService) *managerRuntime {
	return &managerRuntime{service: service}
}

func (runtime *managerRuntime) SetLock(lock io.Closer) error {
	runtime.admissionMu.Lock()
	defer runtime.admissionMu.Unlock()
	if lock == nil {
		return errors.New("manager state lock is nil")
	}
	if err := runtime.lifecycle.transition(managerLocked); err != nil {
		return err
	}
	runtime.lock = lock
	return nil
}

func (runtime *managerRuntime) AddServer(server *http.Server, listener net.Listener, endpoint string) error {
	runtime.admissionMu.Lock()
	defer runtime.admissionMu.Unlock()
	if server == nil || listener == nil {
		return errors.New("manager server and listener are required")
	}
	if phase := runtime.lifecycle.current(); phase != managerLocked && phase != managerListening {
		return fmt.Errorf("add manager server in phase %s", phase)
	}
	runtime.servers = append(runtime.servers, managedServer{server: server, listener: listener, endpoint: endpoint})
	if runtime.lifecycle.current() == managerLocked {
		return runtime.lifecycle.transition(managerListening)
	}
	return nil
}

func (runtime *managerRuntime) FeedsReady(receivers []managerReceiver) error {
	runtime.admissionMu.Lock()
	defer runtime.admissionMu.Unlock()
	if runtime.lifecycle.current() != managerListening {
		return fmt.Errorf("publish manager feeds in phase %s", runtime.lifecycle.current())
	}
	runtime.receivers = append(runtime.receivers, receivers...)
	return runtime.lifecycle.transition(managerFeedsReady)
}

func (runtime *managerRuntime) StartServers() error {
	runtime.admissionMu.Lock()
	defer runtime.admissionMu.Unlock()
	if err := runtime.lifecycle.transition(managerServing); err != nil {
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

func (runtime *managerRuntime) ServeErrors() <-chan error { return runtime.serveErrors }

func (runtime *managerRuntime) Close() error {
	runtime.closeOnce.Do(func() {
		runtime.admissionMu.Lock()
		runtime.lifecycle.beginStop()
		if runtime.service != nil {
			runtime.service.stopAdmission()
		}
		runtime.admissionMu.Unlock()

		var errs []error
		shutdownCtx, cancel := context.WithTimeout(context.Background(), managerShutdownGracePeriod)
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
		if runtime.service != nil {
			runtime.service.joinRequests()
			runtime.service.joinBackground()
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
			_ = runtime.lifecycle.transition(managerFailed)
		} else {
			_ = runtime.lifecycle.transition(managerStopped)
		}
	})
	return runtime.closeErr
}

var errManagerStopping = errors.New("manager is stopping")
