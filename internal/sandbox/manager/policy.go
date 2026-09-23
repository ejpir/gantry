package manager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policyfeed"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlcmd"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/sandbox/manager/operationstate"
)

func (m *managerService) handleGetNetworkPolicy(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	lock := m.sandboxLock(name)
	lock.RLock()
	defer lock.RUnlock()
	entry, err := controlcmd.GetNetworkPolicy(name)
	if err != nil {
		writeManagerError(w, http.StatusConflict, err, "")
		return
	}
	writeManagerJSON(w, http.StatusOK, entry)
}

func (m *managerService) handleSetNetworkPolicy(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	var request managerapi.NetworkPolicyRequest
	body, err := decodeManagerJSON(r, &request)
	if err == nil && request.Default == (len(request.Policy) > 0) {
		err = errors.New("supply exactly one of policy or default=true")
	}
	if err == nil && !request.Default {
		_, err = netpol.Parse(request.Policy)
	}
	if err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	m.runLifecycle(w, r, "net-policy", name, body, http.StatusOK, func(owner operationstate.Owner) error {
		// Check existence before creating an upload directory. Policy uploads
		// must not manufacture a sandbox or overwrite its current policy.
		if _, err := config.ReadSandboxConfig(layout.Dir(name)); err != nil {
			return err
		}
		path := ""
		if !request.Default {
			dir := filepath.Join(layout.Dir(name), "remote-policies")
			if err := localsec.CreateManagerDir(dir); err != nil {
				return err
			}
			// Content addressing keeps the old file immutable until all local
			// validation and live application has succeeded. Failed policies
			// never alter a file referenced by the saved/active configuration.
			path = filepath.Join(dir, fmt.Sprintf("%x.json", sha256.Sum256(request.Policy)))
			if err := atomicfile.WriteFileDurable(path, request.Policy, 0o600); err != nil {
				return err
			}
			if err := localsec.SecureRegularFile(path); err != nil {
				return err
			}
		}
		entry, err := controlcmd.SetNetworkPolicy(name, path, request.AllowLocal)
		if err == nil {
			err = m.operationState.SetProgress(owner, "network policy "+entry.State+": "+entry.Description)
		}
		return err
	})
}

func (m *managerService) handleGetOrganizationPolicy(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	lock := m.sandboxLock(name)
	lock.RLock()
	defer lock.RUnlock()
	cfg, err := config.ReadSandboxConfig(layout.Dir(name))
	if err != nil {
		writeManagerError(w, http.StatusNotFound, err, "")
		return
	}
	result := managerapi.OrganizationPolicy{Managed: cfg.OrgPolicy != nil}
	if cfg.OrgPolicy != nil {
		engine, err := policy.New(cfg.OrgPolicy, nil)
		if err != nil {
			writeManagerError(w, http.StatusConflict, err, "")
			return
		}
		info := engine.Info()
		result.Info = &info
	}
	// Do not return sandbox.json: it contains credential/custody references
	// unrelated to this operation. The response is public provenance only.
	writeManagerJSON(w, http.StatusOK, result)
}

func (m *managerService) handleSetOrganizationPolicy(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	var request managerapi.OrganizationPolicyRequest
	body, err := decodeManagerJSON(r, &request)
	if err == nil && request.Clear == (request.Snapshot != nil) {
		err = errors.New("supply exactly one of snapshot or clear=true")
	}
	if err != nil {
		writeManagerError(w, http.StatusBadRequest, err, "")
		return
	}
	m.runLifecycle(w, r, "policy", name, body, http.StatusOK, func(owner operationstate.Owner) error {
		if active := m.organizationPolicy; active != nil && !sameOrganizationPolicy(request.Snapshot, active) {
			return fmt.Errorf("organization-wide policy feed controls sandbox policy")
		}
		return m.setOrganizationPolicyLocked(r.Context(), name, request.Snapshot, request.Restart, func(message string) {
			_ = m.operationState.SetProgress(owner, message)
		})
	})
}

// setOrganizationPolicyLocked applies a preverified snapshot while the
// manager's per-sandbox mutation lock is held. Running sandboxes reconcile all
// live enforcement points unless restart explicitly requests stop/resume.
func (m *managerService) setOrganizationPolicyLocked(ctx context.Context, name string, snapshot *policy.Config, restart bool, progress func(string)) error {
	return RolloutOrganizationPolicy(ctx, m.lifecycle, name, snapshot, restart, progress)
}

// RolloutOrganizationPolicy updates a stopped sandbox, applies a coherent
// live change when supported, or performs stop/update/resume when restart is
// true. Callers must serialize it with other sandbox mutations.
func RolloutOrganizationPolicy(ctx context.Context, sandboxLifecycle Lifecycle, name string, snapshot *policy.Config, restart bool, progress func(string)) error {
	cfg, err := config.ReadSandboxConfig(layout.Dir(name))
	if err != nil {
		return err
	}
	if _, err := policy.New(snapshot, nil); err != nil {
		return err
	}
	if snapshot != nil && cfg.OAuthCustodyEnabled() {
		return fmt.Errorf("organization policy v1 does not support OAuth custody")
	}
	_, running := layout.PID(name)
	marker, err := readPolicyRolloutMarker(name)
	if err != nil {
		return err
	}
	resumeAfter := marker != nil && marker.Resume
	if sameOrganizationPolicy(cfg.OrgPolicy, snapshot) {
		if resumeAfter && !running {
			if progress != nil {
				progress("resuming interrupted organization policy rollout")
			}
			if _, err := sandboxLifecycle.Start(ctx, lifecycle.StartRequest{Name: name, Mode: lifecycle.Resume}, nil); err != nil {
				return fmt.Errorf("resume interrupted organization policy rollout: %w", err)
			}
			_ = os.Remove(policyRolloutMarkerPath(name))
		} else {
			if running && marker != nil {
				_ = os.Remove(policyRolloutMarkerPath(name))
			}
			if progress != nil {
				progress("organization policy already active or saved")
			}
		}
		return nil
	}
	if running && !restart {
		updater, ok := sandboxLifecycle.(OrganizationPolicyService)
		if !ok {
			return fmt.Errorf("live organization policy is unavailable; request a controlled restart")
		}
		if progress != nil {
			progress("applying organization policy to live enforcement points")
		}
		if err := updater.ApplyOrganizationPolicy(ctx, name, snapshot); err != nil {
			return err
		}
		if progress != nil {
			progress("organization policy active without restart")
		}
		return nil
	}
	if !running && !resumeAfter {
		if err := controlcmd.SetOrganizationPolicy(name, snapshot); err != nil {
			return err
		}
		if progress != nil {
			progress("organization policy saved (takes effect on next start)")
		}
		return nil
	}

	if running {
		if err := writePolicyRolloutMarker(name, policyConfigDigest(snapshot)); err != nil {
			return err
		}
		if progress != nil {
			progress("stopping sandbox for organization policy update")
		}
		if err := sandboxLifecycle.Stop(name); err != nil && !errors.Is(err, ErrNotRunning) {
			if _, stillRunning := layout.PID(name); stillRunning {
				_ = os.Remove(policyRolloutMarkerPath(name))
			}
			return err
		}
	}
	if err := controlcmd.SetOrganizationPolicy(name, snapshot); err != nil {
		// The old configuration is still authoritative. Best-effort recovery
		// avoids turning a validation/storage failure into an outage.
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_, resumeErr := sandboxLifecycle.Start(recoveryCtx, lifecycle.StartRequest{Name: name, Mode: lifecycle.Resume}, nil)
		if resumeErr != nil {
			return errors.Join(err, fmt.Errorf("resume previous policy after failed update: %w", resumeErr))
		}
		_ = os.Remove(policyRolloutMarkerPath(name))
		return err
	}
	if progress != nil {
		progress("organization policy saved; resuming sandbox")
	}
	if _, err := sandboxLifecycle.Start(ctx, lifecycle.StartRequest{Name: name, Mode: lifecycle.Resume}, nil); err != nil {
		return fmt.Errorf("organization policy saved but sandbox remains stopped: %w", err)
	}
	_ = os.Remove(policyRolloutMarkerPath(name))
	if progress != nil {
		progress("organization policy active after controlled restart")
	}
	return nil
}

func sameOrganizationPolicy(left, right *policy.Config) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Profile == right.Profile && left.PublicKey == right.PublicKey && bytes.Equal(left.Bundle, right.Bundle)
}

const policyRolloutMarkerVersion = 1

type policyRolloutMarker struct {
	Version int    `json:"version"`
	Resume  bool   `json:"resume"`
	Digest  string `json:"digest"`
}

func policyRolloutMarkerPath(name string) string {
	return filepath.Join(layout.Dir(name), "policy-rollout.json")
}

func policyConfigDigest(snapshot *policy.Config) string {
	hash := sha256.New()
	if snapshot == nil {
		_, _ = hash.Write([]byte("unmanaged"))
	} else {
		_, _ = hash.Write(snapshot.Bundle)
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(snapshot.PublicKey))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(snapshot.Profile))
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func writePolicyRolloutMarker(name, digest string) error {
	raw, err := json.Marshal(policyRolloutMarker{Version: policyRolloutMarkerVersion, Resume: true, Digest: digest})
	if err != nil {
		return err
	}
	path := policyRolloutMarkerPath(name)
	if err := atomicfile.WriteFileDurable(path, append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("save policy rollout marker: %w", err)
	}
	if err := localsec.SecureRegularFile(path); err != nil {
		return fmt.Errorf("secure policy rollout marker: %w", err)
	}
	return nil
}

func readPolicyRolloutMarker(name string) (*policyRolloutMarker, error) {
	path := policyRolloutMarkerPath(name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect policy rollout marker: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 1024 {
		return nil, fmt.Errorf("invalid policy rollout marker file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 1024 {
		return nil, fmt.Errorf("read policy rollout marker: invalid or unavailable")
	}
	var marker policyRolloutMarker
	if err := json.Unmarshal(raw, &marker); err != nil || marker.Version != policyRolloutMarkerVersion || !marker.Resume || len(marker.Digest) != 64 {
		return nil, fmt.Errorf("invalid policy rollout marker")
	}
	return &marker, nil
}

// applyReceivedOrganizationPolicy publishes one feed generation manager-wide.
// Existing running sandboxes reconcile live, stopped sandboxes save the same
// snapshot, and later creates inherit it while the manager remains active. The
// receiver advances its aggregate cursor only when every target succeeds.
func (m *managerService) applyReceivedOrganizationPolicy(ctx context.Context, update policyfeed.Update) error {
	if update.Snapshot == nil {
		return fmt.Errorf("organization policy feed supplied an empty snapshot")
	}
	engine, err := policy.New(update.Snapshot, nil)
	if err != nil {
		return err
	}
	if info := engine.Info(); info != update.Info {
		return fmt.Errorf("organization policy feed metadata does not match its snapshot")
	}
	if !tryAcquireSlot(m.lifecycleSlots) {
		return fmt.Errorf("manager lifecycle capacity is full")
	}
	defer releaseSlot(m.lifecycleSlots)
	for !m.organizationPolicyMu.TryLock() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.runtime.Context().Done():
			return context.Canceled
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer m.organizationPolicyMu.Unlock()

	// Publish before enumeration and target mutation: even an unreadable state
	// entry cannot let subsequent creates or raw runs escape the received policy.
	m.organizationPolicy = policy.CloneConfig(update.Snapshot)
	names, err := organizationPolicySandboxNames()
	if err != nil {
		return err
	}
	var rolloutErrors []error
	for _, name := range names {
		lock := m.sandboxLock(name)
		// Existing lifecycle mutations drained before the global write lock was
		// acquired. Reads/execs holding this shard are bounded; once publication
		// starts, finish or fail-close every target even if shutdown is requested.
		lock.Lock()
		err := m.setOrganizationPolicyLocked(ctx, name, update.Snapshot, false, nil)
		if err != nil {
			stopErr := m.lifecycle.Stop(name)
			if stopErr != nil && !errors.Is(stopErr, ErrNotRunning) {
				err = errors.Join(err, fmt.Errorf("fail-closed stop: %w", stopErr))
			}
			rolloutErrors = append(rolloutErrors, fmt.Errorf("sandbox %s: %w", name, err))
		}
		lock.Unlock()
	}
	if len(rolloutErrors) == 0 {
		return nil
	}
	// The receiver reports only these counts to the policy service; sandbox
	// names and causes stay in this host's audit log.
	return &policyfeed.RolloutError{Failed: len(rolloutErrors), Total: len(names), Err: errors.Join(rolloutErrors...)}
}

func organizationPolicySandboxNames() ([]string, error) {
	root := layout.Root()
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect organization-policy sandbox root: %w", err)
	}
	// Windows can successfully enumerate a regular file as an empty directory
	// on some filesystems. Check the object type explicitly so a malformed or
	// replaced manager root cannot turn a mandatory rollout into a false
	// aggregate acknowledgement. Symlinks are equally ambiguous here and must
	// fail closed even if their current target happens to be a directory.
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("organization-policy sandbox root is not a secure directory")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("enumerate organization-policy sandboxes: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !layout.ValidName(entry.Name()) {
			continue
		}
		_, err := os.Lstat(filepath.Join(layout.Dir(entry.Name()), "sandbox.json"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect sandbox %s for organization-policy rollout: %w", entry.Name(), err)
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (m *managerService) handleAudit(w http.ResponseWriter, r *http.Request) {
	name, ok := managerSandboxName(w, r)
	if !ok {
		return
	}
	lock := m.sandboxLock(name)
	lock.RLock()
	defer lock.RUnlock()
	if _, err := os.Stat(filepath.Join(layout.Dir(name), "sandbox.json")); err != nil {
		writeManagerError(w, http.StatusNotFound, err, "")
		return
	}
	lines, err := controlcmd.AuditTail(name)
	if err != nil {
		writeManagerError(w, http.StatusConflict, err, "")
		return
	}
	if lines == nil {
		lines = []string{}
	}
	writeManagerJSON(w, http.StatusOK, managerapi.AuditTail{Lines: lines})
}
