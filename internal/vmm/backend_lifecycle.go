package vmm

import (
	"errors"
	"sync"
	"sync/atomic"
)

// nativeBackendLifecycle coordinates hypervisor threads with native resource
// teardown. Every possible worker is reserved before the backend is published
// to Machine, so Close can safely race goroutines that have not been scheduled
// yet. Close stops and kicks workers, joins the claimed workers, and only then
// releases native objects.
type nativeBackendLifecycle struct {
	stopping atomic.Bool
	stopOnce sync.Once
	stopCh   chan struct{}

	pending atomic.Int32
	workers sync.WaitGroup
	errMu   sync.Mutex
	errs    []error

	closeOnce sync.Once
	closeErr  error
}

// nativeThreadTeardown is the second phase used by thread-affine native
// objects. Every owner first leaves its run loop, then all owners are released
// together to destroy their objects on their original threads.
type nativeThreadTeardown struct {
	stopped     sync.WaitGroup
	releaseOnce sync.Once
	releaseCh   chan struct{}
}

func newNativeThreadTeardown(workers int) *nativeThreadTeardown {
	t := &nativeThreadTeardown{releaseCh: make(chan struct{})}
	t.stopped.Add(workers)
	return t
}

func (t *nativeThreadTeardown) finishOwner(release func()) {
	t.stopped.Done()
	<-t.releaseCh
	if release != nil {
		release()
	}
}

func (t *nativeThreadTeardown) releaseOwners() {
	t.stopped.Wait()
	t.releaseOnce.Do(func() { close(t.releaseCh) })
}

func newNativeBackendLifecycle(workerCount int) *nativeBackendLifecycle {
	l := &nativeBackendLifecycle{stopCh: make(chan struct{})}
	l.pending.Store(int32(workerCount))
	l.workers.Add(workerCount)
	return l
}

// claimWorker transfers one pre-reserved WaitGroup slot to its caller. The
// caller must invoke workerDone exactly once after a successful claim.
func (l *nativeBackendLifecycle) claimWorker() bool {
	for {
		remaining := l.pending.Load()
		if remaining == 0 {
			return false
		}
		if l.pending.CompareAndSwap(remaining, remaining-1) {
			return true
		}
	}
}

func (l *nativeBackendLifecycle) workerDone() { l.workers.Done() }

// recordError adds worker-finalization failures to Close. Callers record from
// inside a claimed worker, before workerDone, so Close's join is also an error
// publication barrier.
func (l *nativeBackendLifecycle) recordError(err error) {
	if err == nil {
		return
	}
	l.errMu.Lock()
	l.errs = append(l.errs, err)
	l.errMu.Unlock()
}

func (l *nativeBackendLifecycle) takeErrors() []error {
	l.errMu.Lock()
	defer l.errMu.Unlock()
	errs := l.errs
	l.errs = nil
	return errs
}

func (l *nativeBackendLifecycle) runWorker(run func(<-chan struct{})) {
	if !l.claimWorker() {
		return
	}
	defer l.workerDone()
	if l.isStopping() {
		return
	}
	run(l.stopCh)
}

func (l *nativeBackendLifecycle) isStopping() bool { return l.stopping.Load() }

func (l *nativeBackendLifecycle) stop() {
	l.stopOnce.Do(func() {
		l.stopping.Store(true)
		close(l.stopCh)
	})
}

// close is deliberately callback-based: tests can verify ordering without
// loading Hypervisor.framework or WinHvPlatform.dll, while each backend keeps
// its native calls in its platform file.
func (l *nativeBackendLifecycle) close(kick, release func() error) error {
	l.closeOnce.Do(func() {
		l.stop()

		// Reservations not claimed before stop belong to Close. A goroutine
		// scheduled later observes zero pending slots and returns immediately.
		for range int(l.pending.Swap(0)) {
			l.workers.Done()
		}

		var errs []error
		if kick != nil {
			errs = append(errs, kick())
		}
		l.workers.Wait()
		errs = append(errs, l.takeErrors()...)
		if release != nil {
			errs = append(errs, release())
		}
		l.closeErr = errors.Join(errs...)
	})
	return l.closeErr
}
