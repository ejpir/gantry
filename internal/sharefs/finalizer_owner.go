//go:build linux || darwin || windows

package sharefs

import "sync"

// deferredFinalizers owns export-release workers which must upgrade the
// serving request gate after OnForget returns. Shutdown stops admission while
// holding that gate, releases it, and then joins every admitted worker.
type deferredFinalizers struct {
	mu       sync.Mutex
	stopping bool
	workers  sync.WaitGroup
}

func (owner *deferredFinalizers) schedule(run func()) bool {
	if owner == nil || run == nil {
		return false
	}
	owner.mu.Lock()
	if owner.stopping {
		owner.mu.Unlock()
		return false
	}
	owner.workers.Add(1)
	owner.mu.Unlock()
	go func() {
		defer owner.workers.Done()
		run()
	}()
	return true
}

// stopAdmission must run before the serving request writer gate is released.
// That makes it impossible for an OnForget callback to race Wait with Add.
func (owner *deferredFinalizers) stopAdmission() {
	if owner == nil {
		return
	}
	owner.mu.Lock()
	owner.stopping = true
	owner.mu.Unlock()
}

func (owner *deferredFinalizers) wait() {
	if owner != nil {
		owner.workers.Wait()
	}
}
