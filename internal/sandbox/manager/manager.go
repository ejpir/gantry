package manager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
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
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policyfeed"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/inspection"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

const (
	// readHeaderTimeout bounds how long a local client may dawdle over its
	// request line and headers before the server drops it.
	readHeaderTimeout = 5 * time.Second

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

type managerService struct {
	lifecycle  Lifecycle
	context    context.Context
	cancel     context.CancelFunc
	requests   managerTaskGroup
	background managerTaskGroup

	operationState operationStore
	lifecycleSlots chan struct{}
	execSlots      chan struct{}
	sshSlots       chan struct{}
	sandboxLocks   [64]sync.RWMutex
	rawRunLock     sync.RWMutex

	// organizationPolicyMu is the manager-wide admission barrier. Lifecycle
	// operations and new exec/SSH sessions hold it for reading before taking a
	// sandbox shard; a feed generation holds it for writing while it fans out
	// and publishes the snapshot inherited by later creates.
	organizationPolicyMu sync.RWMutex
	organizationPolicy   *policy.Config
}

func newManagerService(lifecycle Lifecycle) *managerService {
	ctx, cancel := context.WithCancel(context.Background())
	return &managerService{
		lifecycle:      lifecycle,
		context:        ctx,
		cancel:         cancel,
		operationState: newOperationStore(),
		lifecycleSlots: make(chan struct{}, managerMaxLifecycleOps),
		execSlots:      make(chan struct{}, managerMaxExecs),
		sshSlots:       make(chan struct{}, managerMaxExecs),
	}
}

func (m *managerService) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", m.handleHealth)
	mux.HandleFunc("GET /v1/openapi.yaml", m.handleOpenAPI)
	mux.HandleFunc("GET /v1/sandboxes", m.handleListSandboxes)
	mux.HandleFunc("POST /v1/sandboxes", m.handleCreateSandbox)
	mux.HandleFunc("POST /v1/run", m.handleRunVM)
	mux.HandleFunc("PATCH /v1/sandboxes/{name}", m.handleConfigureSandbox)
	mux.HandleFunc("GET /v1/sandboxes/{name}", m.handleGetSandbox)
	mux.HandleFunc("DELETE /v1/sandboxes/{name}", m.handleDeleteSandbox)
	mux.HandleFunc("POST /v1/sandboxes/{name}/start", m.handleStartSandbox)
	mux.HandleFunc("POST /v1/sandboxes/{name}/stop", m.handleStopSandbox)
	mux.HandleFunc("POST /v1/sandboxes/{name}/exec", m.handleExecSandbox)
	mux.HandleFunc("GET /v1/sandboxes/{name}/net-policy", m.handleGetNetworkPolicy)
	mux.HandleFunc("PUT /v1/sandboxes/{name}/net-policy", m.handleSetNetworkPolicy)
	mux.HandleFunc("GET /v1/sandboxes/{name}/policy", m.handleGetOrganizationPolicy)
	mux.HandleFunc("PUT /v1/sandboxes/{name}/policy", m.handleSetOrganizationPolicy)
	mux.HandleFunc("GET /v1/sandboxes/{name}/audit", m.handleAudit)
	mux.HandleFunc("GET /v1/ssh/hostkey", m.handleSSHHostKey)
	mux.HandleFunc("POST /v1/sandboxes/{name}/ssh", m.handleSSH)
	mux.HandleFunc("GET /v1/operations/{id}", m.handleGetOperation)
	mux.HandleFunc("GET /v1/events", m.handleEvents)
	mux.HandleFunc("GET /v1/images", m.handleListImages)
	mux.HandleFunc("POST /v1/images/pull", m.handlePullImage)
	mux.HandleFunc("POST /v1/images/delete", m.handleDeleteImage)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

func (m *managerService) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeManagerJSON(w, http.StatusOK, managerapi.Health{OK: true, Version: managerAPIVersion})
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
	var request managerapi.CreateSandboxRequest
	body, err := decodeManagerJSON(r, &request)
	if err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	if err := layout.ValidateName(request.Name); err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	if request.Image == "" {
		writeManagerError(w, http.StatusBadRequest, errors.New("image is required"), "")
		return
	}
	m.runLifecycle(w, r, "create", request.Name, body, http.StatusCreated, func(owner operationOwner) error {
		if active := m.organizationPolicy; active != nil {
			if request.OrganizationPolicy != nil && !sameOrganizationPolicy(request.OrganizationPolicy, active) {
				return fmt.Errorf("organization-wide policy feed controls sandbox policy")
			}
			request.OrganizationPolicy = policy.CloneConfig(active)
		}
		result, err := m.lifecycle.Start(r.Context(), createStartRequest(request), nil)
		return errors.Join(err, m.operationState.setWarnings(owner, result.Warnings))
	})
}

func (m *managerService) handleStartSandbox(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	m.runLifecycle(w, r, "start", name, nil, http.StatusOK, func(operationOwner) error {
		if active := m.organizationPolicy; active != nil {
			cfg, err := config.ReadSandboxConfig(layout.Dir(name))
			if err != nil {
				return err
			}
			if !sameOrganizationPolicy(cfg.OrgPolicy, active) {
				return fmt.Errorf("sandbox has not accepted the active organization-wide policy generation")
			}
		}
		_, err := m.lifecycle.Start(r.Context(), lifecycle.StartRequest{Name: name, Mode: lifecycle.Resume}, nil)
		return err
	})
}

func (m *managerService) handleStopSandbox(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	m.runLifecycle(w, r, "stop", name, nil, http.StatusOK, func(operationOwner) error {
		err := m.lifecycle.Stop(name)
		if errors.Is(err, ErrNotRunning) {
			if _, statErr := os.Stat(filepath.Join(layout.Dir(name), "sandbox.json")); statErr == nil {
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
	m.runLifecycle(w, r, "delete", name, nil, http.StatusOK, func(operationOwner) error {
		return m.lifecycle.Delete(name)
	})
}

func (m *managerService) handleExecSandbox(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	// A new exec must not enter a still-old sandbox after a manager-wide
	// generation has begun fan-out. Existing execs retain the documented rule
	// that already-delivered operations are not revoked.
	m.organizationPolicyMu.RLock()
	defer m.organizationPolicyMu.RUnlock()
	lock := m.sandboxLock(name)
	lock.RLock()
	defer lock.RUnlock()
	var request managerapi.ExecRequest
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

	result, err := m.lifecycle.Exec(r.Context(), name, ExecRequest{
		Args:           request.Argv,
		Cwd:            request.Cwd,
		Stdin:          request.Stdin,
		Timeout:        time.Duration(request.TimeoutSeconds) * time.Second,
		MaxOutputBytes: request.MaxOutputBytes,
	})
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, ErrExecTimeout):
			status = http.StatusRequestTimeout
		case errors.Is(err, ErrExecOutputLimit):
			status = http.StatusRequestEntityTooLarge
		case strings.Contains(err.Error(), "is not running"):
			status = http.StatusConflict
		}
		writeManagerError(w, status, err, "")
		return
	}
	writeManagerJSON(w, http.StatusOK, managerapi.ExecResult{
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
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = controller.SetWriteDeadline(time.Time{}) }()
	_, _ = fmt.Fprintf(w, ": connected subscriber=%d\nretry: 1000\n\n", id)
	flusher.Flush()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case event, open := <-events:
			if !open {
				return
			}
			_ = controller.SetWriteDeadline(time.Now().Add(10 * time.Second))
			payload, _ := json.Marshal(event)
			if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.ID, event.Type, payload); err != nil {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			_ = controller.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		case <-m.context.Done():
			return
		}
	}
}

func (m *managerService) runLifecycle(w http.ResponseWriter, r *http.Request, kind, name string, body []byte, successStatus int, run func(operationOwner) error) {
	fingerprint := managerFingerprint(r.Method, r.URL.Path, body)
	started, err := m.beginOperation(kind, name, r.Header.Get("Idempotency-Key"), fingerprint)
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, errManagerStopping) {
			status = http.StatusServiceUnavailable
		}
		writeManagerError(w, status, err, "")
		return
	}
	operation, owner := started.Operation, started.Owner
	if started.Replay {
		switch started.Phase {
		case operationRunning:
			writeManagerJSON(w, http.StatusAccepted, operation)
		case operationSucceeded:
			writeManagerJSON(w, http.StatusOK, operation)
		default:
			writeManagerError(w, http.StatusConflict, errors.New(operation.Error), operation.ID)
		}
		return
	}
	if !tryAcquireSlot(m.lifecycleSlots) {
		err = errors.New("too many concurrent lifecycle operations")
		operation = m.finishOperation(owner, err)
		writeManagerError(w, http.StatusServiceUnavailable, err, operation.ID)
		return
	}
	defer releaseSlot(m.lifecycleSlots)
	// Feed rollout takes the write side before any sandbox shard. Keeping the
	// same order here prevents creates, starts, deletes, or policy mutations
	// from slipping between organization-wide enumeration and publication.
	m.organizationPolicyMu.RLock()
	defer m.organizationPolicyMu.RUnlock()
	lock := m.sandboxLock(name)
	if kind == "run" {
		lock = &m.rawRunLock
	}
	// Waiting behind a long-running operation must not outlive the request
	// or manager. Admission above bounds the number of waiters.
	for !lock.TryLock() {
		select {
		case <-r.Context().Done():
			operation = m.finishOperation(owner, r.Context().Err())
			writeManagerError(w, http.StatusRequestTimeout, r.Context().Err(), operation.ID)
			return
		case <-m.context.Done():
			operation = m.finishOperation(owner, context.Canceled)
			writeManagerError(w, http.StatusServiceUnavailable, context.Canceled, operation.ID)
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer lock.Unlock()
	requestErr := r.Context().Err()
	if requestErr == nil {
		requestErr = m.context.Err()
	}
	if err := requestErr; err != nil {
		operation = m.finishOperation(owner, err)
		writeManagerError(w, http.StatusRequestTimeout, err, operation.ID)
		return
	}
	// Another request may have completed while this one waited on its sandbox
	// shard. Recheck the key under the execution lock so identical concurrent
	// retries never perform the lifecycle transition twice.
	if key := r.Header.Get("Idempotency-Key"); key != "" && !m.operationState.ownsIdempotency(owner, key) {
		operation = m.finishOperation(owner, errors.New("idempotent operation was superseded"))
		writeManagerJSON(w, http.StatusAccepted, operation)
		return
	}

	err = run(owner)
	operation = m.finishOperation(owner, err)
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, ErrImageNotFound) || errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeManagerError(w, status, err, operation.ID)
		return
	}
	writeManagerJSON(w, successStatus, operation)
}

func (m *managerService) sandboxLock(name string) *sync.RWMutex {
	digest := sha256.Sum256([]byte(name))
	return &m.sandboxLocks[int(digest[0])%len(m.sandboxLocks)]
}

func (m *managerService) beginOperation(kind, name, key, fingerprint string) (operationStart, error) {
	if m.context.Err() != nil {
		return operationStart{}, errManagerStopping
	}
	return m.operationState.begin(kind, name, key, fingerprint)
}

func (m *managerService) ownedHandler(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		done, ok := m.requests.Acquire()
		if !ok {
			writeManagerError(w, http.StatusServiceUnavailable, errManagerStopping, "")
			return
		}
		defer done()
		inner.ServeHTTP(w, r)
	})
}

func (m *managerService) startBackground(run func(context.Context)) bool {
	return m.background.Start(func() { run(m.context) })
}

func (m *managerService) stopAdmission() {
	m.requests.StopAdmission()
	m.background.StopAdmission()
	m.cancel()
}

func (m *managerService) joinRequests()   { m.requests.Wait() }
func (m *managerService) joinBackground() { m.background.Wait() }

func (m *managerService) finishOperation(owner operationOwner, operationErr error) *managerapi.Operation {
	operation, err := m.operationState.finish(owner, operationErr)
	if err == nil {
		return operation
	}
	if current, ok := m.operationState.operation(owner.ID()); ok {
		return current
	}
	return &managerapi.Operation{ID: owner.ID(), Kind: owner.kind, Sandbox: owner.sandbox, State: operationFailed.String(), Error: err.Error()}
}

func (m *managerService) operation(id string) (*managerapi.Operation, bool) {
	return m.operationState.operation(id)
}

func (m *managerService) subscribe() (uint64, <-chan managerapi.Event, func(), bool) {
	return m.operationState.subscribe()
}

func createStartRequest(request managerapi.CreateSandboxRequest) lifecycle.StartRequest {
	options := config.DefaultRunOptions()
	options.Name, options.Image = request.Name, request.Image
	if request.Kernel != "" {
		options.Kernel = request.Kernel
		options.Explicit.Kernel = true
	}
	if request.Rootfs != "" {
		options.Rootfs = request.Rootfs
		options.Explicit.Rootfs = true
	}
	if request.Runtime != "" {
		options.Runtime = request.Runtime
	}
	if request.ProcessIsolation != "" {
		options.ProcessIsolation = request.ProcessIsolation
	}
	options.OrganizationSnapshot = request.OrganizationPolicy
	options.SSH, options.DevContainers = request.SSH, request.DevContainers
	options.RWLayer = request.RWLayer
	// HTTP creation has always defaulted to read-only. Presence is explicit
	// so the common resolver does not infer a writable layer.
	options.Explicit.RW = true
	if request.RW != nil {
		options.RW = *request.RW
	}
	if request.Net != nil {
		options.Net = *request.Net
	}
	if request.OAuthBridge != nil {
		options.OAuthBridge = *request.OAuthBridge
	}
	options.NetPol, options.AllowLN = request.NetworkPolicy, request.AllowLocalNetwork
	options.ProxyURL, options.NoProxy, options.ProxyEnforce = request.Proxy, request.NoProxy, request.ProxyEnforce
	if request.MemoryMiB != 0 {
		options.MemMB = request.MemoryMiB
		options.Explicit.Memory = true
	}
	if request.CPUs != 0 {
		options.VCPUs = request.CPUs
		options.Explicit.CPUs = true
	}
	if request.DiskSizeMiB != 0 {
		options.RWLayerSizeMiB = request.DiskSizeMiB
		options.Explicit.DiskSize = true
	}
	options.Shares, options.Publish, options.Secrets = request.Shares, request.Publish, request.SecretNames
	return lifecycle.StartRequest{Name: request.Name, Mode: lifecycle.Create, Options: options, CachedOnly: true}
}

func listManagerSandboxes() ([]managerapi.Sandbox, error) {
	entries, err := os.ReadDir(layout.Root())
	if errors.Is(err, os.ErrNotExist) {
		return []managerapi.Sandbox{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]managerapi.Sandbox, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !layout.ValidName(entry.Name()) {
			continue
		}
		sandbox, err := inspectManagerSandbox(entry.Name())
		if err == nil {
			result = append(result, sandbox)
		}
	}
	return result, nil
}

func inspectManagerSandbox(name string) (managerapi.Sandbox, error) {
	snapshot, err := inspection.Inspect(name)
	if err != nil {
		return managerapi.Sandbox{}, err
	}
	if snapshot.ConfigError != nil {
		return managerapi.Sandbox{}, snapshot.ConfigError
	}
	cfg := snapshot.Desired
	imageName := filepath.Base(cfg.Image)
	if cfg.ImageRef != "" {
		imageName = cfg.ImageRef
	}
	noProxy := cfg.NoProxy
	if cfg.ProxyURL != "" && noProxy == "" {
		noProxy = config.DefaultNoProxy
	}
	return managerapi.Sandbox{
		Name: name, State: string(snapshot.State), PID: snapshot.PID, Image: imageName,
		Desired: inspection.Settings(cfg), Active: snapshot.Active, RestartRequired: snapshot.RestartRequired,
		ImageRef: cfg.ImageRef, ImageDigest: cfg.ImageDigest,
		CPUs: cfg.VCPUs, MemoryMiB: cfg.MemMB, Writable: cfg.RW,
		Proxy: cfg.ProxyURL, NoProxy: noProxy, ProxyEnforce: cfg.ProxyEnforce,
	}, nil
}

func validateManagerExec(request *managerapi.ExecRequest) error {
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

func managerBaseDir() string {
	if home := os.Getenv("GANTRY_HOME"); home != "" {
		return filepath.Dir(filepath.Clean(home))
	}
	return filepath.Dir(layout.Root())
}

// SocketPath returns the manager endpoint. GANTRY_MANAGER_SOCKET is an
// explicit test/embedding override; production defaults to ~/.gantry/manager.sock.
func SocketPath() string {
	if path := os.Getenv("GANTRY_MANAGER_SOCKET"); path != "" {
		return path
	}
	return filepath.Join(managerBaseDir(), "manager.sock")
}

// Cmd runs the HTTP/JSON manager over lifecycle. The default listener is the
// same-user Unix socket, whose filesystem permissions are the authentication
// boundary. -listen tls://ADDR:PORT opts into the network transport, which
// requires bearer-token authentication (--token-file) and TLS material
// (--self-signed or --tls-cert/--tls-key); plaintext network listeners are
// refused. An optional -policy-feed adds one outbound mTLS organization-wide
// policy receiver. See docs/gantry/remote-access.md.
func Cmd(argv []string, lifecycle Lifecycle) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	socket := flags.String("socket", "", "deprecated alias for -listen unix://PATH")
	var listens listenFlags
	flags.Var(&listens, "listen", "manager listener: unix://PATH or tls://ADDR:PORT (repeatable); default unix://"+SocketPath())
	selfSigned := flags.Bool("self-signed", false, "generate or reuse self-signed TLS material under <root>/serve/")
	tlsCert := flags.String("tls-cert", "", "TLS certificate chain file (requires --tls-key)")
	tlsKey := flags.String("tls-key", "", "TLS private key file (requires --tls-cert)")
	tokenFile := flags.String("token-file", "", "bearer token file, one token per line (required with tls://)")
	var feedPaths policyFeedFlags
	flags.Var(&feedPaths, "policy-feed", "organization-wide mTLS policy-feed configuration")
	mintToken := flags.Bool("mint-token", false, "print a fresh bearer token and exit")
	if err := flags.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gantry serve [-listen unix://PATH | tls://ADDR:PORT] [--self-signed | --tls-cert C --tls-key K] [--token-file PATH] [--policy-feed CONFIG]")
		fmt.Fprintln(os.Stderr, "       gantry serve --mint-token")
		return 2
	}
	if *mintToken {
		token, err := MintToken()
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry serve:", err)
			return 1
		}
		fmt.Println(token)
		return 0
	}
	plan, err := resolveServePlan(*socket, listens, *tlsCert, *tlsKey, *selfSigned, *tokenFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry serve:", err)
		return 2
	}
	if len(feedPaths) > 1 {
		fmt.Fprintln(os.Stderr, "gantry serve: only one organization-wide policy feed may be configured")
		return 2
	}
	feeds := make([]*policyfeed.Config, 0, len(feedPaths))
	for _, path := range feedPaths {
		feed, err := policyfeed.LoadConfig(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry serve:", err)
			return 2
		}
		feeds = append(feeds, feed)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serveWithOptions(ctx, serveOptions{plan: plan, policyFeeds: feeds}, lifecycle); err != nil {
		fmt.Fprintln(os.Stderr, "gantry serve:", err)
		return 1
	}
	return 0
}

// listenFlags collects repeated -listen occurrences.
type listenFlags []string

func (f *listenFlags) String() string { return strings.Join(*f, ",") }

func (f *listenFlags) Set(value string) error {
	if value == "" {
		return errors.New("empty -listen value")
	}
	*f = append(*f, value)
	return nil
}

type policyFeedFlags []string

func (f *policyFeedFlags) String() string { return strings.Join(*f, ",") }

func (f *policyFeedFlags) Set(value string) error {
	if value == "" {
		return errors.New("empty -policy-feed value")
	}
	*f = append(*f, value)
	return nil
}

// serveManager keeps the historical single-unix-socket entry point for
// existing callers and tests.
func serveManager(socketPath string, lifecycle Lifecycle) error {
	plan, err := resolveServePlan(socketPath, nil, "", "", false, "")
	if err != nil {
		return err
	}
	return serveWithOptions(context.Background(), serveOptions{plan: plan}, lifecycle)
}

// serveOptions carries the validated plan plus injectable log destinations.
type serveOptions struct {
	plan        servePlan
	policyFeeds []*policyfeed.Config
	// audit receives authentication, mutation, and policy-feed records;
	// nil defaults to stderr.
	audit *log.Logger
}

// serveWithOptions runs every planned listener until ctx cancels or one
// fails. One manager process holds one state lock and shares one connection
// budget across listeners; each listener gets the handler appropriate to its
// transport (same-user unix, or bearer-authenticated TLS).
func serveWithOptions(ctx context.Context, options serveOptions, lifecycle Lifecycle) error {
	if len(options.policyFeeds) > 1 {
		return fmt.Errorf("only one organization-wide policy feed may be configured")
	}
	plan := options.plan
	audit := options.audit
	if audit == nil {
		audit = log.New(os.Stderr, "gantry serve: audit: ", log.LstdFlags)
	}
	service := newManagerService(lifecycle)
	owner := newManagerRuntime(service)
	defer func() { _ = owner.Close() }()

	var tlsMaterial *serveTLS
	var auth *tokenAuth
	if plan.hasTLS() {
		var err error
		tlsMaterial, err = loadServeTLS(plan)
		if err != nil {
			return err
		}
		auth, err = newTokenAuth(plan.tokenFile, audit)
		if err != nil {
			return err
		}
	}

	// The lock directory derives from the first unix listener (historical
	// behavior) or the manager base for TLS-only plans, so two managers can
	// never believe they own the same state tree.
	lockBase := managerBaseDir()
	for _, spec := range plan.listeners {
		if spec.network == "unix" {
			lockBase = filepath.Dir(spec.address)
			break
		}
	}
	for _, spec := range plan.listeners {
		// The default manager endpoint shares Gantry's application root.
		// Secure each predictable fallback component before MkdirAll can
		// traverse it.
		if spec.network == "unix" && os.Getenv("GANTRY_MANAGER_SOCKET") == "" && filepath.Clean(spec.address) == filepath.Clean(SocketPath()) {
			if err := layout.EnsureRoot(); err != nil {
				return err
			}
		}
	}
	if err := localsec.CreateManagerDir(lockBase); err != nil {
		return fmt.Errorf("secure manager directory: %w", err)
	}
	stateDir := filepath.Join(lockBase, "manager-state")
	if err := localsec.CreateManagerDir(stateDir); err != nil {
		return fmt.Errorf("create manager state directory: %w", err)
	}
	lock, err := layout.HoldLock(stateDir)
	if err != nil {
		return fmt.Errorf("another manager holds the state lock: %w", err)
	}
	if err := owner.SetLock(lock); err != nil {
		_ = lock.Close()
		return err
	}

	slots := make(chan struct{}, managerMaxConnections)
	for _, spec := range plan.listeners {
		handler := service.handler()
		var listener net.Listener
		endpoint := ""
		sameUserOnly := false
		switch spec.network {
		case "unix":
			socketPath := spec.address
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
			listener, err = net.Listen("unix", socketPath)
			if err != nil {
				return err
			}
			if err := localsec.SecureEndpoint(socketPath); err != nil {
				_ = listener.Close()
				_ = os.Remove(socketPath)
				return fmt.Errorf("secure manager endpoint: %w", err)
			}
			endpoint = socketPath
			sameUserOnly = true
			fmt.Printf("gantry serve: listening on %s\n", spec)
		case "tls":
			plain, err := net.Listen("tcp", spec.address)
			if err != nil {
				return err
			}
			listener = tls.NewListener(plain, tlsMaterial.config)
			handler = service.authenticatedHandler(auth, audit)
			fmt.Printf("gantry serve: listening on %s (tls fingerprint %s; bearer auth required)\n", spec, tlsMaterial.fingerprint)
		default:
			return fmt.Errorf("unsupported listener network %q", spec.network)
		}
		handler = service.ownedHandler(handler)
		server := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: readHeaderTimeout,
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    16 << 10,
			ErrorLog:          log.New(os.Stderr, "gantry serve: http: ", log.LstdFlags),
		}
		limited := &limitedListener{Listener: listener, slots: slots, sameUserOnly: sameUserOnly}
		if err := owner.AddServer(server, limited, endpoint); err != nil {
			_ = listener.Close()
			if endpoint != "" {
				_ = os.Remove(endpoint)
			}
			return err
		}
	}

	feedStateDir := filepath.Join(stateDir, "policy-feeds")
	receivers := make([]*policyfeed.Receiver, 0, len(options.policyFeeds))
	for _, feed := range options.policyFeeds {
		receiver, err := policyfeed.NewReceiver(feed, feedStateDir, audit, service.applyReceivedOrganizationPolicy)
		if err != nil {
			for _, opened := range receivers {
				opened.Close()
			}
			return err
		}
		// Restore the acknowledged signed generation before accepting manager
		// requests. A failed target has already been stopped by the aggregate
		// rollout; retain the receiver so its background loop can retry.
		if err := receiver.Restore(ctx); err != nil && ctx.Err() == nil {
			audit.Printf("policy feed %s: %v", feed.Organization, err)
		}
		receivers = append(receivers, receiver)
	}
	ownedReceivers := make([]managerReceiver, len(receivers))
	for index, receiver := range receivers {
		ownedReceivers[index] = receiver
	}
	if err := owner.FeedsReady(ownedReceivers); err != nil {
		for _, receiver := range receivers {
			receiver.Close()
		}
		return err
	}
	for _, receiver := range receivers {
		if !service.startBackground(func(ctx context.Context) { receiver.Run(ctx) }) {
			return errManagerStopping
		}
	}
	if err := owner.StartServers(); err != nil {
		return err
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-owner.ServeErrors():
	}
	return errors.Join(serveErr, owner.Close())
}

// limitedListener bounds concurrent connections and optionally restricts
// accepted peers to the same account (unix sockets; TLS peers authenticate
// at the HTTP layer instead).
type limitedListener struct {
	net.Listener
	slots        chan struct{}
	sameUserOnly bool
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.sameUserOnly && !localsec.PeerSameUser(connection) {
			_ = connection.Close()
			continue
		}
		if !tryAcquireSlot(l.slots) {
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
