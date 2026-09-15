package manager

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/runvm"
)

func (m *managerService) handleRunVM(w http.ResponseWriter, r *http.Request) {
	request := runvm.Defaults()
	body, err := decodeManagerJSON(r, &request)
	if err == nil {
		err = runvm.Validate(request)
	}
	if err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	service, ok := m.lifecycle.(RunVMService)
	if !ok {
		writeManagerError(w, http.StatusNotImplemented, errors.New("low-level VM runs are unavailable on this manager"), "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(request.TimeoutSeconds)*time.Second)
	defer cancel()
	stop := context.AfterFunc(m.context, cancel)
	defer stop()
	r = r.WithContext(ctx)
	// Raw runs have no saved sandbox name. A dedicated lock serializes them
	// without blocking named sandbox shards; lifecycle admission is bounded.
	m.runLifecycle(w, r, "run", "", body, http.StatusOK, func(op *managerapi.Operation) error {
		if m.organizationPolicy != nil {
			return errors.New("low-level VM runs are disabled while an organization-wide policy feed is active")
		}
		result, err := service.RunVM(ctx, request)
		if len(result.Output) > request.MaxOutputBytes {
			result.Output = result.Output[:request.MaxOutputBytes]
			result.Truncated = true
		}
		m.mu.Lock()
		m.operations[op.ID].Run = &result
		m.mu.Unlock()
		return err
	})
}
