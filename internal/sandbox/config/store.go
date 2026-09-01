package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/mcpspec"
	"github.com/ejpir/gantry/internal/secret"
	"github.com/ejpir/gantry/internal/sharefs"
	"github.com/ejpir/gantry/internal/shares"
	"github.com/ejpir/gantry/internal/vmm"
)

// ConfigStore is the single owner of sandbox.json for a running daemon.
// Both control-plane managers (shares, ports) mutate the persisted
// RunConfig through it, so concurrent or sequential mutations can never
// clobber each other's fields: every mutation applies to the latest
// in-memory copy and the whole file is rewritten under one mutex.
//
// Mutate rolls the in-memory state back when a write fails before replacement.
// A post-replacement durability error keeps the committed state in memory;
// callers can use atomicfile.Committed to avoid rolling back live state that
// now agrees with the on-disk file.
type ConfigStore struct {
	path string
	// configureMu owns the revisioned SSH/Dev Containers/resource transition
	// domain across preparation, persistence, and explicit service
	// reconciliation. The general mutex remains available to unrelated writes.
	configureMu sync.Mutex
	mu          sync.Mutex
	cfg         RunConfig
	write       func(string, []byte, os.FileMode) error
}

// ReadSandboxConfig is the canonical sandbox.json reader.
func ReadSandboxConfig(dir string) (RunConfig, error) {
	b, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		return RunConfig{}, err
	}
	var cfg RunConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return RunConfig{}, fmt.Errorf("corrupt sandbox.json: %w", err)
	}
	if err := ValidateSandboxResources(cfg.MemMB, cfg.VCPUs); err != nil {
		return RunConfig{}, fmt.Errorf("invalid sandbox resources: %w", err)
	}
	if err := ValidateProcessIsolation(cfg.ProcessIsolation); err != nil {
		return RunConfig{}, fmt.Errorf("invalid sandbox process isolation: %w", err)
	}
	if err := ValidateProxyConfig(cfg); err != nil {
		return RunConfig{}, fmt.Errorf("invalid sandbox proxy: %w", err)
	}
	if err := ValidateDevContainers(cfg); err != nil {
		return RunConfig{}, fmt.Errorf("invalid devcontainers profile: %w", err)
	}
	return cfg, nil
}

// ReadSandboxForLaunch reads one validated configuration and eagerly resolves
// only legacy/env secrets. File and exec sources remain in cfg for daemon-side
// use-time resolution. Callers must hold the sandbox launch lock across this
// read and daemon spawn so a concurrent revocation cannot be lost.
func ReadSandboxForLaunch(dir string, getenv func(string) (string, bool)) (RunConfig, map[string]secret.Value, error) {
	cfg, err := ReadSandboxConfig(dir)
	if err != nil {
		return RunConfig{}, nil, err
	}
	covered := make(map[string]bool, len(cfg.SecretSources))
	for _, ns := range cfg.SecretSources {
		covered[ns.Name] = true
	}
	values := map[string]secret.Value{}
	for _, persisted := range cfg.SecretNames {
		ns, err := secret.ParseNamedSource(persisted)
		if err != nil {
			return RunConfig{}, nil, err
		}
		if covered[ns.Name] {
			continue
		}
		resolved, err := secret.ParseSpec(persisted, getenv)
		if err != nil {
			return RunConfig{}, nil, err
		}
		values[resolved.Name] = resolved.Value
	}
	return cfg, values, nil
}

// LoadConfigStore reads the sandbox's current configuration. The store
// starts from the on-disk truth; boot-time consumers should read the same
// snapshot the managers mutate.
func LoadConfigStore(dir string) (*ConfigStore, error) {
	cfg, err := ReadSandboxConfig(dir)
	if err != nil {
		return nil, err
	}
	return &ConfigStore{path: filepath.Join(dir, "sandbox.json"), cfg: cfg}, nil
}

// Snapshot returns an independent copy of the latest persisted configuration.
// Callers may retain or modify the result without racing later mutations.
func (s *ConfigStore) Snapshot() RunConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneRunConfig(s.cfg)
}

// Mutate applies fn to the live configuration and atomically persists the
// result. fn must be pure with respect to the configuration (compute the
// new field values; no I/O). All mutable slices and pointers are cloned before
// fn runs so aliases cannot defeat rollback or escape through Snapshot.
func (s *ConfigStore) Mutate(fn func(*RunConfig) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	backup := cloneRunConfig(s.cfg)
	beforeSettings := sandboxSettingsOf(backup)
	if err := fn(&s.cfg); err != nil {
		s.cfg = backup
		return err
	}
	// The revision belongs to the store, not mutation callbacks. This also
	// detects legacy/general Mutate callers that accidentally change a setting
	// while a revisioned configuration transaction is preparing live work.
	s.cfg.SettingsRevision = backup.SettingsRevision
	if !reflect.DeepEqual(beforeSettings, sandboxSettingsOf(s.cfg)) {
		revision, err := nextSettingsRevision(backup.SettingsRevision)
		if err != nil {
			s.cfg = backup
			return err
		}
		s.cfg.SettingsRevision = revision
	}
	if err := s.writeLocked(); err != nil {
		if !atomicfile.Committed(err) {
			s.cfg = backup
		}
		return err
	}
	return nil
}

func cloneRunConfig(cfg RunConfig) RunConfig {
	cfg.Shares = append([]string(nil), cfg.Shares...)
	cfg.Ports = append([]string(nil), cfg.Ports...)
	cfg.SecretNames = append([]string(nil), cfg.SecretNames...)
	cfg.MCPRemotes = append([]string(nil), cfg.MCPRemotes...)
	cfg.SecretSources = append([]secret.NamedSource(nil), cfg.SecretSources...)
	for i := range cfg.SecretSources {
		cfg.SecretSources[i].Source.Argv = append([]string(nil), cfg.SecretSources[i].Source.Argv...)
	}
	if cfg.ImageCfg != nil {
		cfg.ImageCfg = cloneImageConfig(cfg.ImageCfg)
	}
	if cfg.DevContainersImageCfg != nil {
		cfg.DevContainersImageCfg = cloneImageConfig(cfg.DevContainersImageCfg)
	}
	if cfg.LayerSet != nil {
		layerSet := *cfg.LayerSet
		layerSet.Layers = append([]string(nil), layerSet.Layers...)
		cfg.LayerSet = &layerSet
	}
	if cfg.OAuthBridge != nil {
		enabled := *cfg.OAuthBridge
		cfg.OAuthBridge = &enabled
	}
	if cfg.OAuthCustody != nil {
		enabled := *cfg.OAuthCustody
		cfg.OAuthCustody = &enabled
	}
	return cfg
}

func cloneImageConfig(source *image.Config) *image.Config {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.Env = append([]string(nil), cloned.Env...)
	cloned.Entrypoint = append([]string(nil), cloned.Entrypoint...)
	cloned.Cmd = append([]string(nil), cloned.Cmd...)
	return &cloned
}

var maxSandboxVCPUs = vmm.MaxSupportedVCPUs()

// MaxSandboxVCPUs reports the host/backend limit used by validation and UI
// metadata. Keeping the cached value private prevents callers from changing
// validation policy process-wide.
func MaxSandboxVCPUs() int { return maxSandboxVCPUs }

const (
	MinSandboxMemMB = (vmm.MinMemoryBytes + (1 << 20) - 1) >> 20
	MaxSandboxMemMB = vmm.MaxMemoryBytes >> 20
)

// ValidateDevContainers fails closed before exposing the devices and OCI
// capabilities needed by a nested runtime.
func ValidateDevContainers(cfg RunConfig) error {
	if !cfg.DevContainers {
		return nil
	}
	if !cfg.SSH {
		return fmt.Errorf("profile requires SSH")
	}
	if NormalizeRuntime(cfg.Runtime) != "crun" {
		return fmt.Errorf("profile requires the crun runtime")
	}
	if cfg.DevContainersDiskMiB != 0 {
		if err := ValidateRWLayerSize(cfg.DevContainersDiskMiB); err != nil {
			return fmt.Errorf("profile IDE disk: %w", err)
		}
	}
	return nil
}

// DevContainersProfileUpdate is a host-prepared curated IDE root and its
// paired writable layer. Configure callers attach it to the same transaction
// that enables the profile, so an unusable placeholder is never persisted.
type DevContainersProfileUpdate struct {
	Image    string
	ImageCfg *image.Config
	RWLayer  string
	DiskMiB  uint
}

// MutableSandboxSettings is the complete user-facing settings set shared by
// CLI, dashboard, and control-protocol conversion layers.
type MutableSandboxSettings struct {
	SSH              bool
	DevContainers    bool
	MemMB            uint
	VCPUs            int
	ProcessIsolation string
}

// Update returns an update in which every mutable setting is explicit.
func (settings MutableSandboxSettings) Update() SandboxUpdate {
	return SandboxUpdate{
		SSH: &settings.SSH, DevContainers: &settings.DevContainers,
		MemMB: &settings.MemMB, VCPUs: &settings.VCPUs,
		ProcessIsolation: &settings.ProcessIsolation,
	}
}

// SandboxUpdate contains only explicitly requested mutable settings.
type SandboxUpdate struct {
	SSH                  *bool
	DevContainers        *bool
	DevContainersProfile *DevContainersProfileUpdate
	MemMB                *uint
	VCPUs                *int
	ProcessIsolation     *string
}

func ApplySandboxUpdate(cfg *RunConfig, update SandboxUpdate) error {
	if cfg == nil {
		return fmt.Errorf("sandbox configuration is nil")
	}
	// Persist the historical default when an old/imported profile is next
	// changed, avoiding a permanently ambiguous runtime field.
	cfg.Runtime = NormalizeRuntime(cfg.Runtime)
	if update.SSH != nil {
		cfg.SSH = *update.SSH
	}
	if update.DevContainers != nil {
		enabling := *update.DevContainers && !cfg.DevContainers
		cfg.DevContainers = *update.DevContainers
		if enabling && cfg.DevContainersDiskMiB == 0 {
			cfg.DevContainersDiskMiB = DefaultDevContainersDiskSizeMiB
		}
	}
	if profile := update.DevContainersProfile; profile != nil {
		if !cfg.DevContainers {
			return fmt.Errorf("prepared Dev Containers profile requires the feature to be enabled")
		}
		if profile.Image == "" || profile.ImageCfg == nil || profile.RWLayer == "" || profile.DiskMiB == 0 {
			return fmt.Errorf("prepared Dev Containers profile is incomplete")
		}
		cfg.DevContainersImage = profile.Image
		cfg.DevContainersImageCfg = cloneImageConfig(profile.ImageCfg)
		cfg.DevContainersRWLayer = profile.RWLayer
		cfg.DevContainersDiskMiB = profile.DiskMiB
	}
	if update.MemMB != nil {
		cfg.MemMB = *update.MemMB
	}
	if update.VCPUs != nil {
		cfg.VCPUs = *update.VCPUs
	}
	if update.ProcessIsolation != nil {
		cfg.ProcessIsolation = *update.ProcessIsolation
	}
	if err := ValidateSandboxResources(cfg.MemMB, cfg.VCPUs); err != nil {
		return err
	}
	if err := ValidateProcessIsolation(cfg.ProcessIsolation); err != nil {
		return err
	}
	return ValidateDevContainers(*cfg)
}

// ErrConfigurationConflict means settings changed after a transaction took
// its revisioned snapshot. Callers must start a fresh transaction rather than
// applying or rolling back a stale service plan.
var ErrConfigurationConflict = errors.New("sandbox settings revision conflict")

// sandboxSettings is the complete persistence and rollback domain for live
// services and restart-required VM settings. Keeping this projection in one
// place means a future mutable setting cannot require field-by-field rollback
// logic at every service call site.
type sandboxSettings struct {
	Runtime               string
	SSH                   bool
	DevContainers         bool
	DevContainersImage    string
	DevContainersImageCfg *image.Config
	DevContainersRWLayer  string
	DevContainersDiskMiB  uint
	MemMB                 uint
	VCPUs                 int
	ProcessIsolation      string
}

func sandboxSettingsOf(cfg RunConfig) sandboxSettings {
	return sandboxSettings{
		Runtime: cfg.Runtime, SSH: cfg.SSH, DevContainers: cfg.DevContainers,
		DevContainersImage:    cfg.DevContainersImage,
		DevContainersImageCfg: cloneImageConfig(cfg.DevContainersImageCfg),
		DevContainersRWLayer:  cfg.DevContainersRWLayer,
		DevContainersDiskMiB:  cfg.DevContainersDiskMiB,
		MemMB:                 cfg.MemMB, VCPUs: cfg.VCPUs, ProcessIsolation: cfg.ProcessIsolation,
	}
}

func applySandboxSettings(cfg *RunConfig, settings sandboxSettings) {
	cfg.Runtime = settings.Runtime
	cfg.SSH = settings.SSH
	cfg.DevContainers = settings.DevContainers
	cfg.DevContainersImage = settings.DevContainersImage
	cfg.DevContainersImageCfg = cloneImageConfig(settings.DevContainersImageCfg)
	cfg.DevContainersRWLayer = settings.DevContainersRWLayer
	cfg.DevContainersDiskMiB = settings.DevContainersDiskMiB
	cfg.MemMB = settings.MemMB
	cfg.VCPUs = settings.VCPUs
	cfg.ProcessIsolation = settings.ProcessIsolation
}

func validateSandboxSettings(cfg RunConfig) error {
	if err := ValidateSandboxResources(cfg.MemMB, cfg.VCPUs); err != nil {
		return err
	}
	if err := ValidateProcessIsolation(cfg.ProcessIsolation); err != nil {
		return err
	}
	return ValidateDevContainers(cfg)
}

func nextSettingsRevision(revision uint64) (uint64, error) {
	if revision == ^uint64(0) {
		return 0, fmt.Errorf("sandbox settings revision exhausted")
	}
	return revision + 1, nil
}

// ConfigurationTransaction owns one revisioned settings transition. It holds
// the settings domain lock until Close, but never holds the general store lock
// while callers prepare assets or reconcile services. Unrelated store
// mutations can therefore continue and are merged into Commit and Rollback.
type ConfigurationTransaction struct {
	store             *ConfigStore
	before            RunConfig
	desired           RunConfig
	after             RunConfig
	baseRevision      uint64
	committedRevision uint64
	changed           bool
	completed         bool
	committed         bool
	rolledBack        bool
	closed            bool
}

// BeginConfiguration snapshots and validates a settings update while taking
// exclusive ownership of the settings revision. The caller must Close the
// transaction, normally with defer, after persistence and service
// reconciliation finish.
func (s *ConfigStore) BeginConfiguration(update SandboxUpdate) (*ConfigurationTransaction, error) {
	s.configureMu.Lock()
	s.mu.Lock()
	before := cloneRunConfig(s.cfg)
	s.mu.Unlock()
	tx := &ConfigurationTransaction{
		store: s, before: before, desired: cloneRunConfig(before),
		baseRevision: before.SettingsRevision,
	}
	if err := tx.Amend(update); err != nil {
		tx.Close()
		return nil, err
	}
	return tx, nil
}

// Amend adds a prepared part of the same transition before it is committed.
// Dev Containers preflight uses this to attach verified image and writable
// layer metadata without taking a second, racy configuration snapshot.
func (tx *ConfigurationTransaction) Amend(update SandboxUpdate) error {
	if tx == nil || tx.store == nil || tx.closed {
		return fmt.Errorf("configuration transaction is closed")
	}
	if tx.completed {
		return fmt.Errorf("configuration transaction is already committed")
	}
	candidate := cloneRunConfig(tx.desired)
	if err := ApplySandboxUpdate(&candidate, update); err != nil {
		return err
	}
	tx.desired = candidate
	tx.changed = !reflect.DeepEqual(sandboxSettingsOf(tx.before), sandboxSettingsOf(tx.desired))
	return nil
}

func (tx *ConfigurationTransaction) Before() RunConfig {
	if tx == nil {
		return RunConfig{}
	}
	return cloneRunConfig(tx.before)
}

func (tx *ConfigurationTransaction) Desired() RunConfig {
	if tx == nil {
		return RunConfig{}
	}
	return cloneRunConfig(tx.desired)
}

func (tx *ConfigurationTransaction) After() RunConfig {
	if tx == nil {
		return RunConfig{}
	}
	return cloneRunConfig(tx.after)
}

func (tx *ConfigurationTransaction) Changed() bool { return tx != nil && tx.changed }

// Commit merges the desired settings into the latest full configuration and
// advances SettingsRevision. A conflicting settings mutation is rejected;
// unrelated shares, ports, secrets, and policy changes survive the merge.
func (tx *ConfigurationTransaction) Commit() error {
	if tx == nil || tx.store == nil || tx.closed {
		return fmt.Errorf("configuration transaction is closed")
	}
	if tx.completed {
		return fmt.Errorf("configuration transaction is already committed")
	}
	tx.store.mu.Lock()
	defer tx.store.mu.Unlock()
	if tx.store.cfg.SettingsRevision != tx.baseRevision {
		return fmt.Errorf("%w: expected %d, found %d", ErrConfigurationConflict,
			tx.baseRevision, tx.store.cfg.SettingsRevision)
	}
	if !tx.changed {
		tx.after = cloneRunConfig(tx.store.cfg)
		tx.completed = true
		return nil
	}

	backup := cloneRunConfig(tx.store.cfg)
	applySandboxSettings(&tx.store.cfg, sandboxSettingsOf(tx.desired))
	revision, err := nextSettingsRevision(tx.baseRevision)
	if err != nil {
		tx.store.cfg = backup
		return err
	}
	tx.store.cfg.SettingsRevision = revision
	if err := validateSandboxSettings(tx.store.cfg); err != nil {
		tx.store.cfg = backup
		return err
	}
	tx.after = cloneRunConfig(tx.store.cfg)
	if err := tx.store.writeLocked(); err != nil {
		if !atomicfile.Committed(err) {
			tx.store.cfg = backup
			tx.after = RunConfig{}
			return err
		}
		tx.completed, tx.committed = true, true
		tx.committedRevision = revision
		return err
	}
	tx.completed, tx.committed = true, true
	tx.committedRevision = revision
	return nil
}

// Rollback restores the complete settings snapshot only when the committed
// revision still owns the desired state. It preserves unrelated mutations and
// advances the revision again so stale plans can never become valid later.
func (tx *ConfigurationTransaction) Rollback() error {
	if tx == nil || tx.store == nil || tx.closed {
		return fmt.Errorf("configuration transaction is closed")
	}
	if !tx.committed {
		return fmt.Errorf("configuration transaction was not committed")
	}
	if tx.rolledBack {
		return fmt.Errorf("configuration transaction was already rolled back")
	}
	tx.store.mu.Lock()
	defer tx.store.mu.Unlock()
	if tx.store.cfg.SettingsRevision != tx.committedRevision {
		return fmt.Errorf("%w: expected %d, found %d", ErrConfigurationConflict,
			tx.committedRevision, tx.store.cfg.SettingsRevision)
	}
	backup := cloneRunConfig(tx.store.cfg)
	applySandboxSettings(&tx.store.cfg, sandboxSettingsOf(tx.before))
	revision, err := nextSettingsRevision(tx.committedRevision)
	if err != nil {
		tx.store.cfg = backup
		return err
	}
	tx.store.cfg.SettingsRevision = revision
	if err := validateSandboxSettings(tx.store.cfg); err != nil {
		tx.store.cfg = backup
		return err
	}
	if err := tx.store.writeLocked(); err != nil {
		if !atomicfile.Committed(err) {
			tx.store.cfg = backup
			return err
		}
		tx.rolledBack = true
		return err
	}
	tx.rolledBack = true
	return nil
}

// Close releases the settings transition domain. It is idempotent so callers
// can safely defer it immediately after BeginConfiguration.
func (tx *ConfigurationTransaction) Close() {
	if tx == nil || tx.store == nil || tx.closed {
		return
	}
	tx.closed = true
	tx.store.configureMu.Unlock()
}

func (s *ConfigStore) Configure(update SandboxUpdate) error {
	tx, err := s.BeginConfiguration(update)
	if err != nil {
		return err
	}
	defer tx.Close()
	return tx.Commit()
}

func ValidateSandboxResources(memMB uint, vcpus int) error {
	if uint64(memMB) < MinSandboxMemMB {
		return fmt.Errorf("memory must be at least %d MiB", MinSandboxMemMB)
	}
	if uint64(memMB) > MaxSandboxMemMB {
		return fmt.Errorf("memory must be at most %d MiB", MaxSandboxMemMB)
	}
	return vmm.ValidateResources(uint64(memMB)<<20, vcpus)
}

// SetResources persists the allocation used the next time the VM boots. A
// running machine is intentionally not mutated in place; its broker owns this
// store so the update cannot race live share or port configuration changes.
func (s *ConfigStore) SetResources(memMB uint, vcpus int, processIsolation string) error {
	if err := ValidateSandboxResources(memMB, vcpus); err != nil {
		return err
	}
	if processIsolation != "" {
		if err := ValidateProcessIsolation(processIsolation); err != nil {
			return err
		}
		processIsolation = NormalizeProcessIsolation(processIsolation)
	}
	update := SandboxUpdate{MemMB: &memMB, VCPUs: &vcpus}
	if processIsolation != "" {
		update.ProcessIsolation = &processIsolation
	}
	tx, err := s.BeginConfiguration(update)
	if err != nil {
		return err
	}
	defer tx.Close()
	if processIsolation == "" {
		// Older resource clients omit this setting. Preserve its posture while
		// canonicalizing the legacy empty spelling inside the same revision.
		mode := NormalizeProcessIsolation(tx.Desired().ProcessIsolation)
		if err := tx.Amend(SandboxUpdate{ProcessIsolation: &mode}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *ConfigStore) SetNetworkPolicy(path string, allowLocal bool) error {
	return s.Mutate(func(cfg *RunConfig) error {
		cfg.NetPol = path
		cfg.AllowLN = allowLocal
		return nil
	})
}

// SetMCPRemote adds or replaces one remote server for the next MCP-worker
// launch. The live worker intentionally remains immutable.
func (s *ConfigStore) SetMCPRemote(raw string, replace bool) (mcpspec.Remote, error) {
	remote, err := mcpspec.Parse(raw)
	if err != nil {
		return mcpspec.Remote{}, err
	}
	canonical, err := mcpspec.Encode(remote)
	if err != nil {
		return mcpspec.Remote{}, err
	}
	err = s.Mutate(func(cfg *RunConfig) error {
		index := -1
		for i, configured := range cfg.MCPRemotes {
			parsed, parseErr := mcpspec.Parse(configured)
			if parseErr != nil {
				return fmt.Errorf("bad configured MCP remote %d: %w", i+1, parseErr)
			}
			if parsed.Name == remote.Name {
				if index >= 0 {
					return fmt.Errorf("duplicate configured MCP server %q", remote.Name)
				}
				index = i
			}
		}
		if index >= 0 && !replace {
			return fmt.Errorf("MCP server %q already exists (use replace)", remote.Name)
		}
		if index < 0 && len(cfg.MCPRemotes) >= mcpspec.MaxRemotes {
			return fmt.Errorf("too many remote MCP servers (max %d)", mcpspec.MaxRemotes)
		}
		if index >= 0 {
			cfg.MCPRemotes[index] = canonical
		} else {
			cfg.MCPRemotes = append(cfg.MCPRemotes, canonical)
		}
		cfg.MCP = true
		return nil
	})
	return remote, err
}

// RemoveMCPRemote drops one remote server from the next MCP-worker launch.
// MCP remains enabled because the built-in filesystem server is still
// configured independently.
func (s *ConfigStore) RemoveMCPRemote(name string) error {
	if name == "" || name == "fs" {
		return fmt.Errorf("invalid removable MCP server %q", name)
	}
	return s.Mutate(func(cfg *RunConfig) error {
		remotes := make([]string, 0, len(cfg.MCPRemotes))
		found := false
		for i, configured := range cfg.MCPRemotes {
			parsed, err := mcpspec.Parse(configured)
			if err != nil {
				return fmt.Errorf("bad configured MCP remote %d: %w", i+1, err)
			}
			if parsed.Name == name {
				found = true
				continue
			}
			remotes = append(remotes, configured)
		}
		if !found {
			return fmt.Errorf("MCP server %q is not configured", name)
		}
		cfg.MCPRemotes = remotes
		return nil
	})
}

// SetMCPFilesystem updates the built-in read-only filesystem server for the
// next MCP-worker launch and enables the gateway if necessary.
func (s *ConfigStore) SetMCPFilesystem(root, user string) error {
	root, user, err := NormalizeMCPFilesystem(root, user)
	if err != nil {
		return err
	}
	return s.Mutate(func(cfg *RunConfig) error {
		cfg.MCP = true
		cfg.MCPFSRoot = root
		cfg.MCPFSUser = user
		return nil
	})
}

// SetSecretName records or drops a secret by clean name. Entries may
// carry a host binding ("NAME@host"); matching is by clean name so a
// dashboard/control update or removal applies to the bound form too.
// Setting a previously bound secret keeps its binding — use does not
// imply rebind, and an update is not a rebinding.
func (s *ConfigStore) SetSecretName(name string, present bool) error {
	if err := secret.ValidateName(name); err != nil {
		return err
	}
	return s.Mutate(func(cfg *RunConfig) error {
		names := make([]string, 0, len(cfg.SecretNames)+1)
		keptBound := ""
		for _, existing := range cfg.SecretNames {
			clean, _, err := secret.SplitBinding(secret.HeadOf(existing))
			if err != nil {
				clean = existing // tolerate a legacy malformed entry verbatim
			}
			if clean != name {
				names = append(names, existing)
			} else if strings.ContainsRune(secret.HeadOf(existing), '@') {
				keptBound = existing
			}
		}
		if present {
			entry := name
			if keptBound != "" {
				entry = keptBound
			}
			names = append(names, entry)
			sort.Strings(names)
		}
		cfg.SecretNames = names
		// Keep the source set in lockstep: removal drops the source so a
		// revoked secret cannot re-resolve on restart; a set keeps an
		// existing source (binding + file/exec ref survive an update) and
		// otherwise records the env default, matching v1 resume-from-env.
		srcs := make([]secret.NamedSource, 0, len(cfg.SecretSources)+1)
		keptSource := secret.NamedSource{}
		haveSource := false
		for _, ns := range cfg.SecretSources {
			if ns.Name != name {
				srcs = append(srcs, ns)
			} else {
				keptSource, haveSource = ns, true
			}
		}
		if present {
			if !haveSource {
				keptSource = secret.NamedSource{Name: name, Source: secret.Source{Kind: secret.SourceEnv, Ref: name}}
			}
			srcs = append(srcs, keptSource)
		}
		cfg.SecretSources = srcs
		return nil
	})
}

// SetShareForRestart updates the desired share set without mutating the live
// hub. It is used for explicit container aliases, which are OCI mounts created
// when the sandbox container starts. Validation happens while this store owns
// the configuration lock so a concurrent live share/port mutation cannot race
// the replacement.
func (s *ConfigStore) SetShareForRestart(spec string, replace bool) (shares.Spec, error) {
	share, err := shares.ParseSpec(spec)
	if err != nil {
		return shares.Spec{}, err
	}
	if !filepath.IsAbs(share.Path) {
		return shares.Spec{}, fmt.Errorf("share path must be absolute (got %q)", share.Path)
	}
	identity, err := sharefs.Identify(share.Path)
	if err != nil {
		return shares.Spec{}, err
	}
	share.Path = identity.Path()

	s.mu.Lock()
	defer s.mu.Unlock()
	backup := cloneRunConfig(s.cfg)

	existingShares, err := shares.ParseSpecs(s.cfg.Shares)
	if err != nil {
		return shares.Spec{}, fmt.Errorf("bad configured share: %w", err)
	}
	found := false
	for _, existing := range existingShares {
		if existing.Tag == share.Tag {
			found = true
			continue
		}
		otherIdentity, pathErr := sharefs.Identify(existing.Path)
		if pathErr != nil {
			return shares.Spec{}, fmt.Errorf("share %s: %w", existing.Tag, pathErr)
		}
		if identity.Aliases(otherIdentity) {
			return shares.Spec{}, fmt.Errorf("share %s aliases share %s (%s)", share.Tag, existing.Tag, otherIdentity.Path())
		}
		if identity.Overlaps(otherIdentity) {
			return shares.Spec{}, fmt.Errorf("share %s overlaps share %s (%s)", share.Tag, existing.Tag, otherIdentity.Path())
		}
		if ConfiguredShareTarget(share) == ConfiguredShareTarget(existing) {
			return shares.Spec{}, fmt.Errorf("share tags %q and %q both target %s", existing.Tag, share.Tag, ConfiguredShareTarget(share))
		}
	}
	if found && !replace {
		return shares.Spec{}, fmt.Errorf("share tag %q already exists (use replace)", share.Tag)
	}
	if !found && len(s.cfg.Shares) >= MaxManagedShares {
		return shares.Spec{}, fmt.Errorf("too many shares (max %d)", MaxManagedShares)
	}
	if ContainerPathsOverlap(ConfiguredShareTarget(share), shares.HubInternalPath) {
		return shares.Spec{}, fmt.Errorf("share %s may not cover, sit under, or contain the internal hub path %s", share.Tag, shares.HubInternalPath)
	}

	s.cfg.Shares = ShareSpecsReplacingTag(s.cfg.Shares, share.Tag, ShareConfigSpec(share))
	if err := s.writeLocked(); err != nil {
		if !atomicfile.Committed(err) {
			s.cfg = backup
			return shares.Spec{}, err
		}
		return share, err
	}
	return share, nil
}

// RemoveShareForRestart removes a persisted share without touching a live
// hub. Stopped sandboxes use this path; a running sandbox delegates removal to
// its broker instead so the live namespace and desired configuration move as
// one transaction.
func (s *ConfigStore) RemoveShareForRestart(tag string) (shares.Spec, error) {
	if err := shares.ValidateShareTag(tag); err != nil {
		return shares.Spec{}, err
	}
	var removed shares.Spec
	err := s.Mutate(func(cfg *RunConfig) error {
		configured, err := shares.ParseSpecs(cfg.Shares)
		if err != nil {
			return fmt.Errorf("bad configured share: %w", err)
		}
		found := false
		for _, share := range configured {
			if share.Tag == tag {
				removed = share
				found = true
			}
		}
		if !found {
			return fmt.Errorf("share tag %q not found", tag)
		}
		cfg.Shares = ShareSpecsReplacingTag(cfg.Shares, tag, "")
		return nil
	})
	return removed, err
}

func (s *ConfigStore) writeLocked() error {
	b, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	write := s.write
	if write == nil {
		write = atomicfile.WriteFileDurable
	}
	return write(s.path, append(b, '\n'), 0o600)
}

// WriteSandboxConfig persists cfg as the sandbox's configuration without
// opening a store. The pre-spawn kernel refresh uses it: no daemon owns
// sandbox.json yet, so there is no live store to mutate through.
func WriteSandboxConfig(dir string, cfg RunConfig) error {
	s := &ConfigStore{path: filepath.Join(dir, "sandbox.json"), cfg: cfg}
	return s.writeLocked()
}

// SetWriter replaces the persistence function used by every later mutation.
// It is the store's test seam: callers fail or observe the write path without
// reaching for an unwritable directory. Production code leaves it unset and
// gets atomicfile.WriteFileDurable.
func (s *ConfigStore) SetWriter(write func(string, []byte, os.FileMode) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.write = write
}
