package manager

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/inspection"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"
	"github.com/ejpir/gantry/internal/sandbox/manager/operationstate"
)

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
	m.runLifecycle(w, r, "create", request.Name, body, http.StatusCreated, func(owner operationstate.Owner) error {
		if active := m.organizationPolicy; active != nil {
			if request.OrganizationPolicy != nil && !sameOrganizationPolicy(request.OrganizationPolicy, active) {
				return fmt.Errorf("organization-wide policy feed controls sandbox policy")
			}
			request.OrganizationPolicy = policy.CloneConfig(active)
		}
		result, err := m.lifecycle.Start(r.Context(), createStartRequest(request), nil)
		return errors.Join(err, m.operationState.SetWarnings(owner, result.Warnings))
	})
}

func (m *managerService) handleStartSandbox(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	m.runLifecycle(w, r, "start", name, nil, http.StatusOK, func(operationstate.Owner) error {
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
	m.runLifecycle(w, r, "stop", name, nil, http.StatusOK, func(operationstate.Owner) error {
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
	m.runLifecycle(w, r, "delete", name, nil, http.StatusOK, func(operationstate.Owner) error {
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
