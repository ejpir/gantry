package manager

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlcmd"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

func (m *managerService) handleGetNetworkPolicy(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok { return }
	lock := m.sandboxLock(name); lock.RLock(); defer lock.RUnlock()
	entry, err := controlcmd.GetNetworkPolicy(name)
	if err != nil { writeManagerError(w, http.StatusConflict, err, ""); return }
	writeManagerJSON(w, http.StatusOK, entry)
}

func (m *managerService) handleSetNetworkPolicy(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok { return }
	var request managerapi.NetworkPolicyRequest
	body, err := decodeManagerJSON(r, &request)
	if err == nil && request.Default == (len(request.Policy) > 0) { err = errors.New("supply exactly one of policy or default=true") }
	if err == nil && !request.Default {
		_, err = netpol.Parse(request.Policy)
	}
	if err != nil { writeManagerError(w, http.StatusBadRequest, err, ""); return }
	m.runLifecycle(w, r, "net-policy", name, body, http.StatusOK, func(op *managerapi.Operation) error {
		// Check existence before creating an upload directory. Policy uploads
		// must not manufacture a sandbox or overwrite its current policy.
		if _, err := config.ReadSandboxConfig(layout.Dir(name)); err != nil { return err }
		path := ""
		if !request.Default {
			dir := filepath.Join(layout.Dir(name), "remote-policies")
			if err := localsec.CreateManagerDir(dir); err != nil { return err }
			// Content addressing keeps the old file immutable until all local
			// validation and live application has succeeded. Failed policies
			// never alter a file referenced by the saved/active configuration.
			path = filepath.Join(dir, fmt.Sprintf("%x.json", sha256.Sum256(request.Policy)))
			if err := atomicfile.WriteFileDurable(path, request.Policy, 0o600); err != nil { return err }
			if err := localsec.SecureRegularFile(path); err != nil { return err }
		}
		entry, err := controlcmd.SetNetworkPolicy(name, path, request.AllowLocal)
		if err == nil { m.setOperationProgress(op.ID, "network policy "+entry.State+": "+entry.Description) }
		return err
	})
}

func (m *managerService) handleGetOrganizationPolicy(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok { return }
	lock := m.sandboxLock(name); lock.RLock(); defer lock.RUnlock()
	cfg, err := config.ReadSandboxConfig(layout.Dir(name))
	if err != nil { writeManagerError(w, http.StatusNotFound, err, ""); return }
	result := managerapi.OrganizationPolicy{Managed: cfg.OrgPolicy != nil}
	if cfg.OrgPolicy != nil {
		engine, err := policy.New(cfg.OrgPolicy, nil)
		if err != nil { writeManagerError(w, http.StatusConflict, err, ""); return }
		info := engine.Info(); result.Info = &info
	}
	// Do not return sandbox.json: it contains credential/custody references
	// unrelated to this operation. The response is public provenance only.
	writeManagerJSON(w, http.StatusOK, result)
}

func (m *managerService) handleSetOrganizationPolicy(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok { return }
	var request managerapi.OrganizationPolicyRequest
	body, err := decodeManagerJSON(r, &request)
	if err == nil && request.Clear == (request.Snapshot != nil) { err = errors.New("supply exactly one of snapshot or clear=true") }
	if err != nil { writeManagerError(w, http.StatusBadRequest, err, ""); return }
	m.runLifecycle(w, r, "policy", name, body, http.StatusOK, func(op *managerapi.Operation) error {
		err := controlcmd.SetOrganizationPolicy(name, request.Snapshot)
		if err == nil { m.setOperationProgress(op.ID, "organization policy saved (takes effect on next start)") }
		return err
	})
}

func (m *managerService) handleAudit(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok { return }
	lock := m.sandboxLock(name); lock.RLock(); defer lock.RUnlock()
	if _, err := os.Stat(filepath.Join(layout.Dir(name), "sandbox.json")); err != nil {
		writeManagerError(w, http.StatusNotFound, err, ""); return
	}
	lines, err := controlcmd.AuditTail(name)
	if err != nil { writeManagerError(w, http.StatusConflict, err, ""); return }
	if lines == nil { lines = []string{} }
	writeManagerJSON(w, http.StatusOK, managerapi.AuditTail{Lines: lines})
}
