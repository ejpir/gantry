package manager

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
)

type unprocessedBody struct{ reads int }

func (b *unprocessedBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (*unprocessedBody) Close() error               { return nil }

func TestRunAndConfigureAuthenticateBeforeBody(t *testing.T) {
	auth, _, _ := newTestTokenAuth(t, "test-secret-token-0123456789")
	service := newManagerService(stubLifecycle{})
	defer service.cancel()
	handler := service.authenticatedHandler(auth, log.New(io.Discard, "", 0))
	for _, route := range []struct{ method, path string }{{http.MethodPost, "/v1/run"}, {http.MethodPatch, "/v1/sandboxes/dev"}} {
		for _, token := range []string{"", "Bearer wrong-token-0123456789"} {
			body := &unprocessedBody{}
			request := httptest.NewRequest(route.method, route.path, nil)
			request.Body = body
			if token != "" {
				request.Header.Set("Authorization", token)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden || body.reads != 0 {
				t.Fatalf("%s status=%d body reads=%d", route.path, response.Code, body.reads)
			}
		}
	}
}

func TestQueuedRawRunCancellationDoesNotStartHelper(t *testing.T) {
	called := false
	service := newManagerService(runLifecycleStub{run: func(context.Context, managerapi.RunVMRequest) (managerapi.ExecResult, error) {
		called = true
		return managerapi.ExecResult{}, nil
	}})
	defer service.cancel()
	service.rawRunLock.Lock()
	defer service.rawRunLock.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/v1/run", strings.NewReader(`{"kernel":"/k","rootfs":"/r"}`)).WithContext(ctx)
	response := httptest.NewRecorder()
	service.handler().ServeHTTP(response, request)
	if called || response.Code != http.StatusRequestTimeout {
		t.Fatalf("queued cancellation started=%v status=%d", called, response.Code)
	}
	if running := service.operationState.Stats().Running; running != 0 {
		t.Fatalf("canceled waiter kept %d running operations", running)
	}
}
