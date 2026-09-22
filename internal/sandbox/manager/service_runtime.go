package manager

import (
	"context"
	"net/http"

	"github.com/ejpir/gantry/internal/sandbox/manager/runtimeowner"
)

// managerRuntime exclusively owns service cancellation and admission/joining
// for request and background tasks. The HTTP service borrows its context and
// cannot manipulate task-group state directly.
type managerRuntime struct {
	context    context.Context
	cancel     context.CancelFunc
	requests   runtimeowner.TaskGroup
	background runtimeowner.TaskGroup
}

func newManagerRuntime() *managerRuntime {
	ctx, cancel := context.WithCancel(context.Background())
	return &managerRuntime{context: ctx, cancel: cancel}
}

func (r *managerRuntime) Context() context.Context {
	return r.context
}

func (r *managerRuntime) OwnedHandler(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		done, ok := r.requests.Acquire()
		if !ok {
			writeManagerError(w, http.StatusServiceUnavailable, errManagerStopping, "")
			return
		}
		defer done()
		inner.ServeHTTP(w, request)
	})
}

func (r *managerRuntime) StartBackground(run func(context.Context)) bool {
	return r.background.Start(func() { run(r.context) })
}

func (r *managerRuntime) Cancel() {
	r.cancel()
}

func (r *managerRuntime) StopAdmission() {
	r.requests.StopAdmission()
	r.background.StopAdmission()
	r.Cancel()
}

func (r *managerRuntime) JoinRequests() {
	r.requests.Wait()
}

func (r *managerRuntime) JoinBackground() {
	r.background.Wait()
}

func (m *managerService) ownedHandler(inner http.Handler) http.Handler {
	return m.runtime.OwnedHandler(inner)
}

func (m *managerService) startBackground(run func(context.Context)) bool {
	return m.runtime.StartBackground(run)
}

// cancel remains a narrow test/lifecycle adapter: it cancels in-flight work
// without independently changing task admission.
func (m *managerService) cancel() {
	m.runtime.Cancel()
}

func (m *managerService) stopAdmission() {
	m.runtime.StopAdmission()
}

func (m *managerService) joinRequests() {
	m.runtime.JoinRequests()
}

func (m *managerService) joinBackground() {
	m.runtime.JoinBackground()
}
