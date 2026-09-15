package manager

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/image"
)

func (m *managerService) imageService(w http.ResponseWriter) (ImageService, bool) {
	service, ok := m.lifecycle.(ImageService)
	if !ok {
		writeManagerError(w, http.StatusNotImplemented, errors.New("image service unavailable"), "")
	}
	return service, ok
}

func (m *managerService) handleListImages(w http.ResponseWriter, _ *http.Request) {
	service, ok := m.imageService(w)
	if !ok {
		return
	}
	images, err := service.ListImages()
	if err != nil {
		writeManagerError(w, http.StatusInternalServerError, err, "")
		return
	}
	if images == nil {
		images = []managerapi.Image{}
	}
	writeManagerJSON(w, http.StatusOK, managerapi.ImageList{Images: images})
}

// Pull accepts registry references only. Normalizing before passing argv to
// the helper excludes flags, local files and credential-bearing URLs.
func validateImagePull(request *managerapi.ImagePullRequest) error {
	if len(request.Ref) == 0 || len(request.Ref) > 512 || strings.HasPrefix(request.Ref, "-") ||
		strings.ContainsAny(request.Ref, "\\ \t\r\n\x00?#") || strings.Contains(request.Ref, "://") {
		return errors.New("ref must be an OCI registry reference (not a path or URL)")
	}
	ref, err := image.ParseRef(request.Ref)
	if err != nil {
		return err
	}
	request.Ref = ref.String()
	request.Platform = strings.TrimPrefix(request.Platform, "linux/")
	if request.Platform != "" && request.Platform != "amd64" && request.Platform != "arm64" {
		return errors.New("platform must be linux/amd64 or linux/arm64")
	}
	return nil
}

func (m *managerService) handlePullImage(w http.ResponseWriter, r *http.Request) {
	service, ok := m.imageService(w)
	if !ok {
		return
	}
	var request managerapi.ImagePullRequest
	body, err := decodeManagerJSON(r, &request)
	if err == nil {
		err = validateImagePull(&request)
	}
	if err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	operation, replay, err := m.beginOperation("image-pull", "", r.Header.Get("Idempotency-Key"), managerFingerprint(r.Method, r.URL.Path, body))
	if err != nil {
		writeManagerError(w, http.StatusConflict, err, "")
		return
	}
	if !replay {
		if !tryAcquireSlot(m.lifecycleSlots) {
			err := errors.New("too many concurrent lifecycle operations")
			m.finishOperation(operation.ID, err)
			writeManagerError(w, http.StatusServiceUnavailable, err, operation.ID)
			return
		}
		m.background.Add(1)
		go func() {
			defer m.background.Done()
			defer releaseSlot(m.lifecycleSlots)
			// Independent of r.Context: disconnects do not cancel committed
			// work. Shutdown still cancels and reaps the short-lived helper.
			ctx, cancel := context.WithTimeout(m.context, time.Hour)
			defer cancel()
			img, err := service.PullImage(ctx, request.Ref, request.Platform, func(line string) {
				m.setOperationProgress(operation.ID, line)
			})
			if err == nil {
				m.setOperationProgress(operation.ID, fmt.Sprintf("cached %s as %s", img.Ref, img.Digest))
			}
			m.finishOperation(operation.ID, err)
		}()
	}
	status := http.StatusAccepted
	if operation.State != "running" {
		status = http.StatusOK
	}
	writeManagerJSON(w, status, operation)
}

func (m *managerService) handleDeleteImage(w http.ResponseWriter, r *http.Request) {
	service, ok := m.imageService(w)
	if !ok {
		return
	}
	var request managerapi.ImageDeleteRequest
	body, err := decodeManagerJSON(r, &request)
	if err != nil || request.Ref == "" || len(request.Ref) > 512 {
		writeManagerError(w, http.StatusBadRequest, errors.New("ref is required (maximum 512 bytes)"), "")
		return
	}
	m.runLifecycle(w, r, "image-delete", "", body, http.StatusOK, func(op *managerapi.Operation) error {
		_, err := service.DeleteImage(request.Ref)
		if err == nil {
			m.setOperationProgress(op.ID, "removed "+request.Ref)
		}
		return err
	})
}

func (m *managerService) setOperationProgress(id, line string) {
	if len(line) > 4096 {
		line = line[:4096]
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if operation := m.operations[id]; operation != nil {
		operation.Progress = line
		operation.Updated = time.Now().UTC()
	}
}
