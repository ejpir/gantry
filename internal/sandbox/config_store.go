package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/ejpir/gantry/internal/atomicfile"
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
	path  string
	mu    sync.Mutex
	cfg   RunConfig
	write func(string, []byte, os.FileMode) error
}

// readSandboxConfig is the canonical sandbox.json reader.
func readSandboxConfig(dir string) (RunConfig, error) {
	b, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		return RunConfig{}, err
	}
	var cfg RunConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return RunConfig{}, fmt.Errorf("corrupt sandbox.json: %w", err)
	}
	if err := validateSandboxResources(cfg.MemMB, cfg.VCPUs); err != nil {
		return RunConfig{}, fmt.Errorf("invalid sandbox resources: %w", err)
	}
	if err := validateProcessIsolation(cfg.ProcessIsolation); err != nil {
		return RunConfig{}, fmt.Errorf("invalid sandbox process isolation: %w", err)
	}
	return cfg, nil
}

// LoadConfigStore reads the sandbox's current configuration. The store
// starts from the on-disk truth; boot-time consumers should read the same
// snapshot the managers mutate.
func LoadConfigStore(dir string) (*ConfigStore, error) {
	cfg, err := readSandboxConfig(dir)
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
// new field values; no I/O). The Shares and Ports slices are cloned before
// fn runs so rollback cannot be defeated by aliasing; mutations to other
// fields are still rolled back by value.
func (s *ConfigStore) Mutate(fn func(*RunConfig) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	backup := cloneRunConfig(s.cfg)
	if err := fn(&s.cfg); err != nil {
		s.cfg = backup
		return err
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
	if cfg.ImageCfg != nil {
		imageCfg := *cfg.ImageCfg
		imageCfg.Env = append([]string(nil), imageCfg.Env...)
		imageCfg.Entrypoint = append([]string(nil), imageCfg.Entrypoint...)
		imageCfg.Cmd = append([]string(nil), imageCfg.Cmd...)
		cfg.ImageCfg = &imageCfg
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
	return cfg
}

const maxSandboxVCPUs = vmm.MaxVCPUs

const (
	minSandboxMemMB = (vmm.MinMemoryBytes + (1 << 20) - 1) >> 20
	maxSandboxMemMB = vmm.MaxMemoryBytes >> 20
)

func validateSandboxResources(memMB uint, vcpus int) error {
	if uint64(memMB) < minSandboxMemMB {
		return fmt.Errorf("memory must be at least %d MiB", minSandboxMemMB)
	}
	if uint64(memMB) > maxSandboxMemMB {
		return fmt.Errorf("memory must be at most %d MiB", maxSandboxMemMB)
	}
	return vmm.ValidateResources(uint64(memMB)<<20, vcpus)
}

// SetResources persists the allocation used the next time the VM boots. A
// running machine is intentionally not mutated in place; its broker owns this
// store so the update cannot race live share or port configuration changes.
func (s *ConfigStore) SetResources(memMB uint, vcpus int, processIsolation string) error {
	if err := validateSandboxResources(memMB, vcpus); err != nil {
		return err
	}
	mode := processIsolation
	if mode != "" {
		if err := validateProcessIsolation(mode); err != nil {
			return err
		}
	}
	return s.Mutate(func(cfg *RunConfig) error {
		// An omitted/empty mode comes from resource-control clients that
		// predate this field. Preserve their configured posture. The TUI sends
		// the explicit spelling "auto" when that is what the user selects.
		if mode == "" {
			mode = cfg.ProcessIsolation
		}
		if err := validateProcessIsolation(mode); err != nil {
			return err
		}
		cfg.MemMB = memMB
		cfg.VCPUs = vcpus
		cfg.ProcessIsolation = normalizedProcessIsolation(mode)
		return nil
	})
}

func (s *ConfigStore) SetNetworkPolicy(path string, allowLocal bool) error {
	return s.Mutate(func(cfg *RunConfig) error {
		cfg.NetPol = path
		cfg.AllowLN = allowLocal
		return nil
	})
}

func (s *ConfigStore) SetSecretName(name string, present bool) error {
	if err := secret.ValidateName(name); err != nil {
		return err
	}
	return s.Mutate(func(cfg *RunConfig) error {
		names := make([]string, 0, len(cfg.SecretNames)+1)
		for _, existing := range cfg.SecretNames {
			if existing != name {
				names = append(names, existing)
			}
		}
		if present {
			names = append(names, name)
			sort.Strings(names)
		}
		cfg.SecretNames = names
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
		if configuredShareTarget(share) == configuredShareTarget(existing) {
			return shares.Spec{}, fmt.Errorf("share tags %q and %q both target %s", existing.Tag, share.Tag, configuredShareTarget(share))
		}
	}
	if found && !replace {
		return shares.Spec{}, fmt.Errorf("share tag %q already exists (use replace)", share.Tag)
	}
	if !found && len(s.cfg.Shares) >= maxManagedShares {
		return shares.Spec{}, fmt.Errorf("too many shares (max %d)", maxManagedShares)
	}
	if containerPathsOverlap(configuredShareTarget(share), shares.HubInternalPath) {
		return shares.Spec{}, fmt.Errorf("share %s may not cover, sit under, or contain the internal hub path %s", share.Tag, shares.HubInternalPath)
	}

	s.cfg.Shares = shareSpecsReplacingTag(s.cfg.Shares, share.Tag, shareConfigSpec(share))
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
		cfg.Shares = shareSpecsReplacingTag(cfg.Shares, tag, "")
		return nil
	})
	return removed, err
}

func configuredShareTarget(share shares.Spec) string {
	if share.CtrPath != "" {
		return share.CtrPath
	}
	return defaultHubCtrPath(share.Tag)
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
