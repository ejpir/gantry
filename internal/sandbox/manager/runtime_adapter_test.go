package manager

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
