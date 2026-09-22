package manager

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
)

const (
	managerEventWriteTimeout = 10 * time.Second
	managerEventHeartbeat    = 15 * time.Second
	managerEventRetryMillis  = 1000
	managerMaxOperationID    = 128
)

func (m *managerService) handleGetOperation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || len(id) > managerMaxOperationID || strings.ContainsAny(id, "/\\\x00") {
		writeManagerError(w, http.StatusBadRequest, errors.New("invalid operation id"), "")
		return
	}
	operation, ok := m.operation(id)
	if !ok {
		writeManagerError(w, http.StatusNotFound, errors.New("operation not found"), "")
		return
	}
	writeManagerJSON(w, http.StatusOK, operation)
}

func (m *managerService) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeManagerError(w, http.StatusInternalServerError, errors.New("streaming unavailable"), "")
		return
	}
	id, events, cancel, ok := m.subscribe()
	if !ok {
		writeManagerError(w, http.StatusServiceUnavailable, errors.New("too many event subscribers"), "")
		return
	}
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	controller := http.NewResponseController(w)
	setManagerEventDeadline(controller)
	defer func() { _ = controller.SetWriteDeadline(time.Time{}) }()
	_, _ = fmt.Fprintf(w, ": connected subscriber=%d\nretry: %d\n\n", id, managerEventRetryMillis)
	flusher.Flush()
	heartbeat := time.NewTicker(managerEventHeartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case event, open := <-events:
			if !open || !writeManagerEvent(w, flusher, controller, event) {
				return
			}
		case <-heartbeat.C:
			setManagerEventDeadline(controller)
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		case <-m.runtime.Context().Done():
			return
		}
	}
}

func writeManagerEvent(w io.Writer, flusher http.Flusher, controller *http.ResponseController, event managerapi.Event) bool {
	setManagerEventDeadline(controller)
	payload, err := json.Marshal(event)
	if err != nil {
		return false
	}
	if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.ID, event.Type, payload); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

func setManagerEventDeadline(controller *http.ResponseController) {
	_ = controller.SetWriteDeadline(time.Now().Add(managerEventWriteTimeout))
}
