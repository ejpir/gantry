package manager

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func managerSandboxName(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("name")
	if err := layout.ValidateName(name); err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return "", false
	}
	return name, true
}

func decodeManagerJSON(r *http.Request, destination any) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, managerMaxRequestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	if len(body) > managerMaxRequestBytes {
		return nil, fmt.Errorf("request body exceeds %d bytes", managerMaxRequestBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return nil, fmt.Errorf("decode request JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("request body must contain one JSON object")
	}
	return body, nil
}

func writeManagerJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeManagerError(w http.ResponseWriter, status int, err error, operationID string) {
	message := http.StatusText(status)
	if err != nil && err.Error() != "" {
		message = err.Error()
	}
	writeManagerJSON(w, status, managerapi.ErrorResponse{Error: message, OperationID: operationID})
}

func managerFingerprint(method, path string, body []byte) string {
	digest := sha256.Sum256(append([]byte(method+"\x00"+path+"\x00"), body...))
	return hex.EncodeToString(digest[:])
}
