package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/secret"
)

const (
	managerAPIVersion          = "v1"
	managerMaxRequestBytes     = 1 << 20
	managerMaxOperations       = 1024
	managerMaxConnections      = 64
	managerMaxLifecycleOps     = 8
	managerMaxExecs            = 32
	managerMaxSubscribers      = 64
	managerEventBuffer         = 32
	managerDefaultOutputBytes  = 1 << 20
	managerMaximumOutputBytes  = 16 << 20
	managerDefaultExecTimeout  = 30 * time.Second
	managerMaximumExecTimeout  = time.Hour
	managerShutdownGracePeriod = 10 * time.Second
)

type managerOperation struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`
	Sandbox  string    `json:"sandbox,omitempty"`
	State    string    `json:"state"`
	Error    string    `json:"error,omitempty"`
	Warnings []string  `json:"warnings,omitempty"`
	Created  time.Time `json:"createdAt"`
	Updated  time.Time `json:"updatedAt"`

	idempotencyKey string
	fingerprint    string
}

type managerEvent struct {
	ID          uint64    `json:"id"`
	Type        string    `json:"type"`
	OperationID string    `json:"operationId,omitempty"`
	Sandbox     string    `json:"sandbox,omitempty"`
	State       string    `json:"state,omitempty"`
	Time        time.Time `json:"time"`
}

type managerSandbox struct {
	Name        string `json:"name"`
	State       string `json:"state"`
	PID         int    `json:"pid,omitempty"`
	Image       string `json:"image,omitempty"`
	ImageRef    string `json:"imageRef,omitempty"`
	ImageDigest string `json:"imageDigest,omitempty"`
	CPUs        int    `json:"cpus,omitempty"`
	MemoryMiB   uint   `json:"memoryMiB,omitempty"`
	Writable    bool   `json:"writable"`
}

type managerCreateRequest struct {
	Name              string   `json:"name"`
	Image             string   `json:"image"`
	Kernel            string   `json:"kernel,omitempty"`
	Rootfs            string   `json:"rootfs,omitempty"`
	Runtime           string   `json:"runtime,omitempty"`
	RW                *bool    `json:"rw,omitempty"`
	RWLayer           string   `json:"rwlayer,omitempty"`
	Shares            []string `json:"shares,omitempty"`
	Publish           []string `json:"publish,omitempty"`
	Net               *bool    `json:"net,omitempty"`
	NetworkPolicy     string   `json:"networkPolicy,omitempty"`
	AllowLocalNetwork bool     `json:"allowLocalNetwork,omitempty"`
	OAuthBridge       *bool    `json:"oauthBridge,omitempty"`
	ProcessIsolation  string   `json:"processIsolation,omitempty"`
	MemoryMiB         uint     `json:"memoryMiB,omitempty"`
	DiskSizeMiB       uint     `json:"diskSizeMiB,omitempty"`
	CPUs              int      `json:"cpus,omitempty"`
	SecretNames       []string `json:"secretNames,omitempty"`
}

type managerExecRequest struct {
	Argv           []string `json:"argv"`
	Cwd            string   `json:"cwd,omitempty"`
	Stdin          string   `json:"stdin,omitempty"`
	TimeoutSeconds int      `json:"timeoutSeconds,omitempty"`
	MaxOutputBytes int64    `json:"maxOutputBytes,omitempty"`
}

type managerExecResponse struct {
	ExitCode  int    `json:"exitCode"`
	Output    string `json:"output"`
	Truncated bool   `json:"truncated"`
}

type managerErrorResponse struct {
	Error       string `json:"error"`
	OperationID string `json:"operationId,omitempty"`
}

type managerIdempotency struct {
	operationID string
	fingerprint string
}

type managerService struct {
	mu             sync.Mutex
	operations     map[string]*managerOperation
	operationOrder []string
	idempotency    map[string]managerIdempotency
	subscribers    map[uint64]chan managerEvent
	nextSubscriber uint64
	nextEvent      uint64
	lifecycleSlots chan struct{}
	execSlots      chan struct{}
	sandboxLocks   [64]sync.RWMutex
}

func newManagerService() *managerService {
	return &managerService{
		operations:     make(map[string]*managerOperation),
		idempotency:    make(map[string]managerIdempotency),
		subscribers:    make(map[uint64]chan managerEvent),
		lifecycleSlots: make(chan struct{}, managerMaxLifecycleOps),
		execSlots:      make(chan struct{}, managerMaxExecs),
	}
}

func (m *managerService) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", m.handleHealth)
	mux.HandleFunc("GET /v1/openapi.yaml", m.handleOpenAPI)
	mux.HandleFunc("GET /v1/sandboxes", m.handleListSandboxes)
	mux.HandleFunc("POST /v1/sandboxes", m.handleCreateSandbox)
	mux.HandleFunc("GET /v1/sandboxes/{name}", m.handleGetSandbox)
	mux.HandleFunc("DELETE /v1/sandboxes/{name}", m.handleDeleteSandbox)
	mux.HandleFunc("POST /v1/sandboxes/{name}/start", m.handleStartSandbox)
	mux.HandleFunc("POST /v1/sandboxes/{name}/stop", m.handleStopSandbox)
	mux.HandleFunc("POST /v1/sandboxes/{name}/exec", m.handleExecSandbox)
	mux.HandleFunc("GET /v1/operations/{id}", m.handleGetOperation)
	mux.HandleFunc("GET /v1/events", m.handleEvents)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

func (m *managerService) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeManagerJSON(w, http.StatusOK, map[string]any{"ok": true, "version": managerAPIVersion})
}

func (m *managerService) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(managerapi.OpenAPI)
}

func (m *managerService) handleListSandboxes(w http.ResponseWriter, _ *http.Request) {
	sandboxes, err := listManagerSandboxes()
	if err != nil {
		writeManagerError(w, http.StatusInternalServerError, err, "")
		return
	}
	writeManagerJSON(w, http.StatusOK, map[string]any{"sandboxes": sandboxes})
}

func (m *managerService) handleGetSandbox(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	sandbox, err := inspectManagerSandbox(name)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeManagerError(w, status, err, "")
		return
	}
	writeManagerJSON(w, http.StatusOK, sandbox)
}

func (m *managerService) handleCreateSandbox(w http.ResponseWriter, r *http.Request) {
	var request managerCreateRequest
	body, err := decodeManagerJSON(r, &request)
	if err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	if err := ValidateSandboxName(request.Name); err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	if request.Image == "" {
		writeManagerError(w, http.StatusBadRequest, errors.New("image is required"), "")
		return
	}
	m.runLifecycle(w, r, "create", request.Name, body, http.StatusCreated, func(operation *managerOperation) error {
		if _, err := os.Stat(filepath.Join(sandboxDir(request.Name), "sandbox.json")); err == nil {
			return fmt.Errorf("sandbox %q already exists", request.Name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		cfg, secrets, warnings, err := resolveManagerCreate(request)
		if err != nil {
			return err
		}
		m.setOperationWarnings(operation.ID, warnings)
		var output, errorOutput bytes.Buffer
		if status := launchSandboxModeWithSpawnerTimingIO(request.Name, cfg, secrets, true, false, startSandboxDaemon, nil, &output, &errorOutput); status != 0 {
			return managerCommandError(errorOutput.String(), output.String(), "sandbox start failed")
		}
		return nil
	})
}

func (m *managerService) handleStartSandbox(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	m.runLifecycle(w, r, "start", name, nil, http.StatusOK, func(*managerOperation) error {
		cfg, secrets, err := loadManagerStart(name)
		if err != nil {
			return err
		}
		var output, errorOutput bytes.Buffer
		if status := launchSandboxModeWithSpawnerTimingIO(name, cfg, secrets, false, false, startSandboxDaemon, nil, &output, &errorOutput); status != 0 {
			return managerCommandError(errorOutput.String(), output.String(), "sandbox start failed")
		}
		return nil
	})
}

func (m *managerService) handleStopSandbox(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	m.runLifecycle(w, r, "stop", name, nil, http.StatusOK, func(*managerOperation) error {
		err := stopSandbox(name)
		if errors.Is(err, errSandboxNotRunning) {
			if _, statErr := os.Stat(filepath.Join(sandboxDir(name), "sandbox.json")); statErr == nil {
				return nil // an already-stopped existing sandbox satisfies stop
			}
		}
		return err
	})
}

func (m *managerService) handleDeleteSandbox(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	m.runLifecycle(w, r, "delete", name, nil, http.StatusOK, func(*managerOperation) error {
		return deleteSandbox(name) // RemoveAll makes repeated deletes idempotent.
	})
}

func (m *managerService) handleExecSandbox(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	lock := m.sandboxLock(name)
	lock.RLock()
	defer lock.RUnlock()
	var request managerExecRequest
	if _, err := decodeManagerJSON(r, &request); err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	if err := validateManagerExec(&request); err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	if !tryAcquireSlot(m.execSlots) {
		writeManagerError(w, http.StatusServiceUnavailable, errors.New("too many concurrent exec requests"), "")
		return
	}
	defer releaseSlot(m.execSlots)

	result, err := execSandboxCaptured(name, capturedExecRequest{
		Context:        r.Context(),
		Args:           request.Argv,
		Cwd:            request.Cwd,
		Stdin:          strings.NewReader(request.Stdin),
		Timeout:        time.Duration(request.TimeoutSeconds) * time.Second,
		MaxOutputBytes: request.MaxOutputBytes,
	})
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, errCapturedExecTimeout):
			status = http.StatusRequestTimeout
		case errors.Is(err, errCapturedExecOutputLimit):
			status = http.StatusRequestEntityTooLarge
		case strings.Contains(err.Error(), "is not running"):
			status = http.StatusConflict
		}
		writeManagerError(w, status, err, "")
		return
	}
	writeManagerJSON(w, http.StatusOK, managerExecResponse{
		ExitCode:  result.ExitCode,
		Output:    string(result.Output),
		Truncated: result.Truncated,
	})
}

func (m *managerService) handleGetOperation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || len(id) > 128 || strings.ContainsAny(id, "/\\\x00") {
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
	_, _ = fmt.Fprintf(w, ": connected subscriber=%d\n\n", id)
	flusher.Flush()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case event, open := <-events:
			if !open {
				return
			}
			payload, _ := json.Marshal(event)
			if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.ID, event.Type, payload); err != nil {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (m *managerService) runLifecycle(w http.ResponseWriter, r *http.Request, kind, name string, body []byte, successStatus int, run func(*managerOperation) error) {
	fingerprint := managerFingerprint(r.Method, r.URL.Path, body)
	operation, replay, err := m.beginOperation(kind, name, r.Header.Get("Idempotency-Key"), fingerprint)
	if err != nil {
		writeManagerError(w, http.StatusConflict, err, "")
		return
	}
	if replay {
		switch operation.State {
		case "running":
			writeManagerJSON(w, http.StatusAccepted, operation)
		case "succeeded":
			writeManagerJSON(w, http.StatusOK, operation)
		default:
			writeManagerError(w, http.StatusConflict, errors.New(operation.Error), operation.ID)
		}
		return
	}
	if !tryAcquireSlot(m.lifecycleSlots) {
		err = errors.New("too many concurrent lifecycle operations")
		operation = m.finishOperation(operation.ID, err)
		writeManagerError(w, http.StatusServiceUnavailable, err, operation.ID)
		return
	}
	defer releaseSlot(m.lifecycleSlots)
	lock := m.sandboxLock(name)
	lock.Lock()
	defer lock.Unlock()
	// Another request may have completed while this one waited on its sandbox
	// shard. Recheck the key under the execution lock so identical concurrent
	// retries never perform the lifecycle transition twice.
	if key := r.Header.Get("Idempotency-Key"); key != "" {
		m.mu.Lock()
		current := m.idempotency[key]
		owner := current.operationID == operation.ID
		m.mu.Unlock()
		if !owner {
			operation = m.finishOperation(operation.ID, errors.New("idempotent operation was superseded"))
			writeManagerJSON(w, http.StatusAccepted, operation)
			return
		}
	}

	err = run(operation)
	operation = m.finishOperation(operation.ID, err)
	if err != nil {
		writeManagerError(w, http.StatusConflict, err, operation.ID)
		return
	}
	writeManagerJSON(w, successStatus, operation)
}

func (m *managerService) sandboxLock(name string) *sync.RWMutex {
	digest := sha256.Sum256([]byte(name))
	return &m.sandboxLocks[int(digest[0])%len(m.sandboxLocks)]
}

func (m *managerService) beginOperation(kind, name, key, fingerprint string) (*managerOperation, bool, error) {
	if err := validateIdempotencyKey(key); err != nil {
		return nil, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if key != "" {
		if existing, ok := m.idempotency[key]; ok {
			if existing.fingerprint != fingerprint {
				return nil, false, fmt.Errorf("idempotency key was already used for a different request")
			}
			operation, ok := m.operations[existing.operationID]
			if !ok {
				return nil, false, fmt.Errorf("idempotency record expired; use a new key")
			}
			return cloneManagerOperation(operation), true, nil
		}
	}
	if len(m.operations) >= managerMaxOperations && !m.removeOldestCompletedOperationLocked() {
		return nil, false, fmt.Errorf("operation capacity is full")
	}
	now := time.Now().UTC()
	operation := &managerOperation{
		ID: newManagerOperationID(), Kind: kind, Sandbox: name,
		State: "running", Created: now, Updated: now,
		idempotencyKey: key, fingerprint: fingerprint,
	}
	m.operations[operation.ID] = operation
	m.operationOrder = append(m.operationOrder, operation.ID)
	if key != "" {
		m.idempotency[key] = managerIdempotency{operationID: operation.ID, fingerprint: fingerprint}
	}
	m.pruneOperationsLocked()
	m.publishLocked("operation", operation)
	return cloneManagerOperation(operation), false, nil
}

func (m *managerService) setOperationWarnings(id string, warnings []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if operation := m.operations[id]; operation != nil {
		operation.Warnings = append([]string(nil), warnings...)
		operation.Updated = time.Now().UTC()
	}
}

func (m *managerService) finishOperation(id string, operationErr error) *managerOperation {
	m.mu.Lock()
	defer m.mu.Unlock()
	operation := m.operations[id]
	if operation == nil {
		return &managerOperation{ID: id, State: "failed", Error: "operation record lost"}
	}
	if operationErr != nil {
		operation.State = "failed"
		operation.Error = operationErr.Error()
	} else {
		operation.State = "succeeded"
	}
	operation.Updated = time.Now().UTC()
	m.publishLocked("operation", operation)
	return cloneManagerOperation(operation)
}

func (m *managerService) operation(id string) (*managerOperation, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	operation, ok := m.operations[id]
	return cloneManagerOperation(operation), ok
}

func cloneManagerOperation(operation *managerOperation) *managerOperation {
	if operation == nil {
		return nil
	}
	copy := *operation
	copy.Warnings = append([]string(nil), operation.Warnings...)
	copy.idempotencyKey = ""
	copy.fingerprint = ""
	return &copy
}

func (m *managerService) pruneOperationsLocked() {
	for len(m.operations) > managerMaxOperations {
		if !m.removeOldestCompletedOperationLocked() {
			return
		}
	}
}

func (m *managerService) removeOldestCompletedOperationLocked() bool {
	for index, id := range m.operationOrder {
		operation := m.operations[id]
		if operation != nil && operation.State == "running" {
			continue
		}
		m.operationOrder = append(m.operationOrder[:index], m.operationOrder[index+1:]...)
		delete(m.operations, id)
		if operation != nil && operation.idempotencyKey != "" {
			delete(m.idempotency, operation.idempotencyKey)
		}
		return true
	}
	return false
}

func (m *managerService) publishLocked(eventType string, operation *managerOperation) {
	m.nextEvent++
	event := managerEvent{
		ID: m.nextEvent, Type: eventType, OperationID: operation.ID,
		Sandbox: operation.Sandbox, State: operation.State, Time: time.Now().UTC(),
	}
	for id, subscriber := range m.subscribers {
		select {
		case subscriber <- event:
		default:
			close(subscriber)
			delete(m.subscribers, id)
		}
	}
}

func (m *managerService) subscribe() (uint64, <-chan managerEvent, func(), bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.subscribers) >= managerMaxSubscribers {
		return 0, nil, nil, false
	}
	m.nextSubscriber++
	id := m.nextSubscriber
	channel := make(chan managerEvent, managerEventBuffer)
	m.subscribers[id] = channel
	cancel := func() {
		m.mu.Lock()
		if current, ok := m.subscribers[id]; ok && current == channel {
			delete(m.subscribers, id)
			close(channel)
		}
		m.mu.Unlock()
	}
	return id, channel, cancel, true
}

func resolveManagerCreate(request managerCreateRequest) (RunConfig, map[string]secret.Value, []string, error) {
	fs := flag.NewFlagSet("manager-create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	flags := RegisterRunFlags(fs)
	flags.Name = request.Name
	set := func(name, value string) error {
		if err := fs.Set(name, value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	}
	for _, setting := range []struct{ name, value string }{
		{"image", request.Image}, {"kernel", request.Kernel}, {"rootfs", request.Rootfs},
		{"runtime", request.Runtime}, {"rwlayer", request.RWLayer}, {"net-policy", request.NetworkPolicy},
		{"process-isolation", request.ProcessIsolation},
	} {
		if setting.value != "" {
			if err := set(setting.name, setting.value); err != nil {
				return RunConfig{}, nil, nil, err
			}
		}
	}
	// The manager API intentionally defaults to read-only and network enabled.
	rw := false
	if request.RW != nil {
		rw = *request.RW
	}
	if err := set("rw", fmt.Sprint(rw)); err != nil {
		return RunConfig{}, nil, nil, err
	}
	network := true
	if request.Net != nil {
		network = *request.Net
	}
	if err := set("net", fmt.Sprint(network)); err != nil {
		return RunConfig{}, nil, nil, err
	}
	oauth := true
	if request.OAuthBridge != nil {
		oauth = *request.OAuthBridge
	}
	if err := set("oauth-bridge", fmt.Sprint(oauth)); err != nil {
		return RunConfig{}, nil, nil, err
	}
	if request.AllowLocalNetwork {
		if err := set("allow-local-net", "true"); err != nil {
			return RunConfig{}, nil, nil, err
		}
	}
	if request.MemoryMiB != 0 {
		if err := set("mem", fmt.Sprint(request.MemoryMiB)); err != nil {
			return RunConfig{}, nil, nil, err
		}
	}
	if request.DiskSizeMiB != 0 {
		if err := set("disk-size", fmt.Sprint(request.DiskSizeMiB)); err != nil {
			return RunConfig{}, nil, nil, err
		}
	}
	if request.CPUs != 0 {
		if err := set("cpus", fmt.Sprint(request.CPUs)); err != nil {
			return RunConfig{}, nil, nil, err
		}
	}
	for _, share := range request.Shares {
		if err := set("share", share); err != nil {
			return RunConfig{}, nil, nil, err
		}
	}
	for _, publish := range request.Publish {
		if err := set("publish", publish); err != nil {
			return RunConfig{}, nil, nil, err
		}
	}
	for _, name := range request.SecretNames {
		if err := set("secret", name); err != nil {
			return RunConfig{}, nil, nil, err
		}
	}
	cfg, warnings, err := flags.resolveWithPolicy(fs, nil, nil, true)
	if err != nil {
		return RunConfig{}, nil, warnings, err
	}
	secrets, _, err := flags.ResolveSecrets()
	return cfg, secrets, warnings, err
}

func loadManagerStart(name string) (RunConfig, map[string]secret.Value, error) {
	cfg, err := readSandboxConfig(sandboxDir(name))
	if err != nil {
		return RunConfig{}, nil, fmt.Errorf("sandbox %q has no valid saved configuration: %w", name, err)
	}
	secrets := make(map[string]secret.Value, len(cfg.SecretNames))
	for _, secretName := range cfg.SecretNames {
		name, value, err := secret.Parse(secretName, os.LookupEnv)
		if err != nil {
			return RunConfig{}, nil, err
		}
		secrets[name] = value
	}
	return cfg, secrets, nil
}

func listManagerSandboxes() ([]managerSandbox, error) {
	entries, err := os.ReadDir(sandboxRoot())
	if errors.Is(err, os.ErrNotExist) {
		return []managerSandbox{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]managerSandbox, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !validSandboxName(entry.Name()) {
			continue
		}
		sandbox, err := inspectManagerSandbox(entry.Name())
		if err == nil {
			result = append(result, sandbox)
		}
	}
	return result, nil
}

func inspectManagerSandbox(name string) (managerSandbox, error) {
	cfg, err := readSandboxConfig(sandboxDir(name))
	if err != nil {
		return managerSandbox{}, err
	}
	state := "stopped"
	pid, alive := sandboxPID(name)
	if alive {
		state = "running"
	} else {
		pid = 0
	}
	imageName := filepath.Base(cfg.Image)
	if cfg.ImageRef != "" {
		imageName = cfg.ImageRef
	}
	return managerSandbox{
		Name: name, State: state, PID: pid, Image: imageName,
		ImageRef: cfg.ImageRef, ImageDigest: cfg.ImageDigest,
		CPUs: cfg.VCPUs, MemoryMiB: cfg.MemMB, Writable: cfg.RW,
	}, nil
}

func validateManagerExec(request *managerExecRequest) error {
	if len(request.Argv) == 0 || len(request.Argv) > 256 {
		return fmt.Errorf("argv must contain between 1 and 256 entries")
	}
	for _, argument := range request.Argv {
		if len(argument) > 32<<10 || strings.ContainsRune(argument, 0) {
			return fmt.Errorf("argv contains an invalid or oversized entry")
		}
	}
	if request.Cwd != "" {
		if len(request.Cwd) > 4096 || strings.ContainsRune(request.Cwd, 0) || !strings.HasPrefix(request.Cwd, "/") {
			return fmt.Errorf("cwd must be an absolute guest path of at most 4096 bytes")
		}
	}
	if len(request.Stdin) > managerMaxRequestBytes {
		return fmt.Errorf("stdin exceeds %d bytes", managerMaxRequestBytes)
	}
	if request.TimeoutSeconds == 0 {
		request.TimeoutSeconds = int(managerDefaultExecTimeout / time.Second)
	}
	if request.TimeoutSeconds < 1 || time.Duration(request.TimeoutSeconds)*time.Second > managerMaximumExecTimeout {
		return fmt.Errorf("timeoutSeconds must be between 1 and %d", int(managerMaximumExecTimeout/time.Second))
	}
	if request.MaxOutputBytes == 0 {
		request.MaxOutputBytes = managerDefaultOutputBytes
	}
	if request.MaxOutputBytes < 1 || request.MaxOutputBytes > managerMaximumOutputBytes {
		return fmt.Errorf("maxOutputBytes must be between 1 and %d", managerMaximumOutputBytes)
	}
	return nil
}

func managerSandboxName(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("name")
	if err := ValidateSandboxName(name); err != nil {
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
	writeManagerJSON(w, status, managerErrorResponse{Error: message, OperationID: operationID})
}

func managerCommandError(errorOutput, output, fallback string) error {
	message := strings.TrimSpace(errorOutput)
	if message == "" {
		message = strings.TrimSpace(output)
	}
	if message == "" {
		message = fallback
	}
	return errors.New(message)
}

func managerFingerprint(method, path string, body []byte) string {
	digest := sha256.Sum256(append([]byte(method+"\x00"+path+"\x00"), body...))
	return hex.EncodeToString(digest[:])
}

func validateIdempotencyKey(key string) error {
	if key == "" {
		return nil
	}
	if len(key) > 128 {
		return fmt.Errorf("idempotency key exceeds 128 bytes")
	}
	for _, character := range key {
		if character < 0x21 || character > 0x7e {
			return fmt.Errorf("idempotency key must contain printable non-space ASCII")
		}
	}
	return nil
}

func newManagerOperationID() string {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err == nil {
		return hex.EncodeToString(entropy[:])
	}
	return fmt.Sprintf("op-%d", time.Now().UnixNano())
}

func managerBaseDir() string {
	if home := os.Getenv("GANTRY_HOME"); home != "" {
		return filepath.Dir(filepath.Clean(home))
	}
	return filepath.Dir(sandboxRoot())
}

// ManagerSocketPath returns the manager endpoint. GANTRY_MANAGER_SOCKET is an
// explicit test/embedding override; production defaults to ~/.gantry/manager.sock.
func ManagerSocketPath() string {
	if path := os.Getenv("GANTRY_MANAGER_SOCKET"); path != "" {
		return path
	}
	return filepath.Join(managerBaseDir(), "manager.sock")
}

// CmdServe runs the same-user local HTTP/JSON manager. It deliberately accepts
// only a filesystem Unix-socket path; remote transport requires a separate,
// explicitly authenticated mTLS gateway.
func CmdServe(argv []string) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	socket := flags.String("socket", ManagerSocketPath(), "Unix-domain manager socket")
	if err := flags.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *socket == "" || strings.ContainsRune(*socket, 0) {
		fmt.Fprintln(os.Stderr, "usage: gantry serve [-socket ~/.gantry/manager.sock]")
		return 2
	}
	if err := serveManager(*socket); err != nil {
		fmt.Fprintln(os.Stderr, "gantry serve:", err)
		return 1
	}
	return 0
}

func serveManager(socketPath string) error {
	base := filepath.Dir(socketPath)
	if err := createManagerDirectory(base); err != nil {
		return fmt.Errorf("secure manager directory: %w", err)
	}
	stateDir := filepath.Join(base, "manager-state")
	if err := createManagerDirectory(stateDir); err != nil {
		return fmt.Errorf("create manager state directory: %w", err)
	}
	lock, err := holdSandboxLock(stateDir)
	if err != nil {
		return fmt.Errorf("another manager holds %s: %w", socketPath, err)
	}
	defer func() { _ = lock.Close() }()

	if conn, err := net.DialTimeout("unix", socketPath, 200*time.Millisecond); err == nil {
		_ = conn.Close()
		return fmt.Errorf("manager is already listening on %s", socketPath)
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to remove non-socket manager endpoint %s", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect stale socket: %w", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()
	if err := secureLocalEndpoint(socketPath); err != nil {
		return fmt.Errorf("secure manager endpoint: %w", err)
	}

	service := newManagerService()
	server := &http.Server{
		Handler:           service.handler(),
		ReadHeaderTimeout: controlHandshakeTimeout,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(os.Stderr, "gantry serve: http: ", log.LstdFlags),
	}
	secureListener := &sameUserManagerListener{Listener: listener, slots: make(chan struct{}, managerMaxConnections)}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	shutdownDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), managerShutdownGracePeriod)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		close(shutdownDone)
	}()
	fmt.Printf("gantry serve: listening on %s\n", socketPath)
	err = server.Serve(secureListener)
	if errors.Is(err, http.ErrServerClosed) {
		<-shutdownDone
		return nil
	}
	return err
}

type sameUserManagerListener struct {
	net.Listener
	slots chan struct{}
}

func (l *sameUserManagerListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if !peerSameUser(connection) || !tryAcquireSlot(l.slots) {
			_ = connection.Close()
			continue
		}
		return &managerCountedConn{Conn: connection, release: func() { releaseSlot(l.slots) }}, nil
	}
}

type managerCountedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *managerCountedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
