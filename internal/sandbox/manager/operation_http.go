package manager

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/manager/operationstate"
)

const managerLifecycleLockPoll = 10 * time.Millisecond

type lifecycleCall struct {
	response      http.ResponseWriter
	request       *http.Request
	kind          string
	sandbox       string
	body          []byte
	successStatus int
	run           func(operationstate.Owner) error
}

// lifecycleAdmission owns all locks and the concurrency slot acquired for one
// lifecycle transition. Close releases them once in reverse acquisition order.
type lifecycleAdmission struct {
	service *managerService
	lock    *sync.RWMutex
	once    sync.Once
}

func (a *lifecycleAdmission) Close() {
	if a == nil {
		return
	}
	a.once.Do(func() {
		a.lock.Unlock()
		a.service.organizationPolicyMu.RUnlock()
		releaseSlot(a.service.lifecycleSlots)
	})
}

func (m *managerService) runLifecycle(w http.ResponseWriter, r *http.Request, kind, name string, body []byte, successStatus int, run func(operationstate.Owner) error) {
	m.executeLifecycle(lifecycleCall{
		response: w, request: r, kind: kind, sandbox: name, body: body,
		successStatus: successStatus, run: run,
	})
}

func (m *managerService) executeLifecycle(call lifecycleCall) {
	started, ok := m.beginLifecycleCall(call)
	if !ok {
		return
	}
	if started.Replay {
		writeLifecycleReplay(call.response, started)
		return
	}
	admission, ok := m.admitLifecycleCall(call, started.Owner)
	if !ok {
		return
	}
	defer admission.Close()
	if !m.lifecycleCallReady(call, started.Owner) {
		return
	}
	m.completeLifecycleCall(call, started.Owner)
}

func (m *managerService) beginLifecycleCall(call lifecycleCall) (operationstate.Start, bool) {
	request := call.request
	fingerprint := managerFingerprint(request.Method, request.URL.Path, call.body)
	started, err := m.beginOperation(call.kind, call.sandbox, request.Header.Get("Idempotency-Key"), fingerprint)
	if err == nil {
		return started, true
	}
	status := http.StatusConflict
	if errors.Is(err, errManagerStopping) {
		status = http.StatusServiceUnavailable
	}
	writeManagerError(call.response, status, err, "")
	return operationstate.Start{}, false
}

func (m *managerService) admitLifecycleCall(call lifecycleCall, owner operationstate.Owner) (*lifecycleAdmission, bool) {
	admission, status, err := m.acquireLifecycleAdmission(call.request.Context(), call.kind, call.sandbox)
	if err == nil {
		return admission, true
	}
	operation := m.finishOperation(owner, err)
	writeManagerError(call.response, status, err, operation.ID)
	return nil, false
}

func (m *managerService) lifecycleCallReady(call lifecycleCall, owner operationstate.Owner) bool {
	if err := firstContextError(call.request.Context(), m.runtime.Context()); err != nil {
		operation := m.finishOperation(owner, err)
		writeManagerError(call.response, http.StatusRequestTimeout, err, operation.ID)
		return false
	}
	// Recheck under the execution lock so identical concurrent retries never
	// perform the lifecycle transition twice.
	key := call.request.Header.Get("Idempotency-Key")
	if key == "" || m.operationState.OwnsIdempotency(owner, key) {
		return true
	}
	operation := m.finishOperation(owner, errors.New("idempotent operation was superseded"))
	writeManagerJSON(call.response, http.StatusAccepted, operation)
	return false
}

func (m *managerService) completeLifecycleCall(call lifecycleCall, owner operationstate.Owner) {
	err := call.run(owner)
	operation := m.finishOperation(owner, err)
	if err != nil {
		writeManagerError(call.response, lifecycleFailureStatus(err), err, operation.ID)
		return
	}
	writeManagerJSON(call.response, call.successStatus, operation)
}

func (m *managerService) acquireLifecycleAdmission(requestCtx context.Context, kind, sandbox string) (*lifecycleAdmission, int, error) {
	if !tryAcquireSlot(m.lifecycleSlots) {
		return nil, http.StatusServiceUnavailable, errors.New("too many concurrent lifecycle operations")
	}
	// Feed rollout takes the write side before any sandbox shard. Keeping the
	// same order here prevents lifecycle mutations from slipping between
	// organization-wide enumeration and publication.
	m.organizationPolicyMu.RLock()
	lock := m.lifecycleExecutionLock(kind, sandbox)
	status, err := m.waitForLifecycleLock(requestCtx, lock)
	if err != nil {
		m.organizationPolicyMu.RUnlock()
		releaseSlot(m.lifecycleSlots)
		return nil, status, err
	}
	return &lifecycleAdmission{service: m, lock: lock}, 0, nil
}

func (m *managerService) lifecycleExecutionLock(kind, sandbox string) *sync.RWMutex {
	if kind == "run" {
		return &m.rawRunLock
	}
	return m.sandboxLock(sandbox)
}

func (m *managerService) waitForLifecycleLock(requestCtx context.Context, lock *sync.RWMutex) (int, error) {
	for !lock.TryLock() {
		select {
		case <-requestCtx.Done():
			return http.StatusRequestTimeout, requestCtx.Err()
		case <-m.runtime.Context().Done():
			return http.StatusServiceUnavailable, context.Canceled
		case <-time.After(managerLifecycleLockPoll):
		}
	}
	return 0, nil
}

func firstContextError(requestCtx, managerCtx context.Context) error {
	if err := requestCtx.Err(); err != nil {
		return err
	}
	return managerCtx.Err()
}

func writeLifecycleReplay(w http.ResponseWriter, started operationstate.Start) {
	switch started.Phase {
	case operationstate.Running:
		writeManagerJSON(w, http.StatusAccepted, started.Operation)
	case operationstate.Succeeded:
		writeManagerJSON(w, http.StatusOK, started.Operation)
	default:
		writeManagerError(w, http.StatusConflict, errors.New(started.Operation.Error), started.Operation.ID)
	}
}

func lifecycleFailureStatus(err error) int {
	if errors.Is(err, ErrImageNotFound) || errors.Is(err, os.ErrNotExist) {
		return http.StatusNotFound
	}
	return http.StatusConflict
}
