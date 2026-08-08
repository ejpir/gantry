package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ejpir/gantry/internal/shares"
	"github.com/ejpir/gantry/internal/vmm"
)

// ConfigStore is the single owner of sandbox.json for a running daemon.
// Both control-plane managers (shares, ports) mutate the persisted
// RunConfig through it, so concurrent or sequential mutations can never
// clobber each other's fields: every mutation applies to the latest
// in-memory copy and the whole file is rewritten under one mutex.
//
// Mutate rolls the in-memory state back when the write fails, so a failed
// mutation leaves no half-applied configuration behind.
type ConfigStore struct {
	path string
	mu   sync.Mutex
	cfg  RunConfig
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

// Snapshot returns the latest persisted configuration. Slice fields share
// storage with the store; callers must not mutate them.
func (s *ConfigStore) Snapshot() RunConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Mutate applies fn to the live configuration and atomically persists the
// result. fn must be pure with respect to the configuration (compute the
// new field values; no I/O). The Shares and Ports slices are cloned before
// fn runs so rollback cannot be defeated by aliasing; mutations to other
// fields are still rolled back by value.
func (s *ConfigStore) Mutate(fn func(*RunConfig) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	backup := s.cfg
	backup.Shares = append([]string(nil), s.cfg.Shares...)
	backup.Ports = append([]string(nil), s.cfg.Ports...)
	if err := fn(&s.cfg); err != nil {
		s.cfg = backup
		return err
	}
	if err := s.writeLocked(); err != nil {
		s.cfg = backup
		return err
	}
	return nil
}

const maxSandboxVCPUs = 8

// maxSandboxMemMB bounds the persisted allocation at 1 TiB: a stray extra
// zero on the CLI should not write a value the VMM can never satisfy at
// the next boot.
const maxSandboxMemMB = 1 << 20

func validateSandboxResources(memMB uint, vcpus int) error {
	if memMB == 0 {
		return fmt.Errorf("memory must be at least 1 MiB")
	}
	if memMB > maxSandboxMemMB {
		return fmt.Errorf("memory must be at most %d MiB", maxSandboxMemMB)
	}
	if vcpus < 1 || vcpus > maxSandboxVCPUs {
		return fmt.Errorf("CPUs must be between 1 and %d", maxSandboxVCPUs)
	}
	return nil
}

// SetResources persists the allocation used the next time the VM boots. A
// running machine is intentionally not mutated in place; its broker owns this
// store so the update cannot race live share or port configuration changes.
func (s *ConfigStore) SetResources(memMB uint, vcpus int) error {
	if err := validateSandboxResources(memMB, vcpus); err != nil {
		return err
	}
	return s.Mutate(func(cfg *RunConfig) error {
		cfg.MemMB = memMB
		cfg.VCPUs = vcpus
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

// SetShareForRestart updates the desired share set without mutating the live
// hub. It is used for explicit container aliases, which are OCI mounts created
// when the sandbox container starts. Validation happens while this store owns
// the configuration lock so a concurrent live share/port mutation cannot race
// the replacement.
func (s *ConfigStore) SetShareForRestart(spec string, replace bool) (vmm.Share, error) {
	share, err := vmm.ParseShareSpec(spec, map[string]bool{})
	if err != nil {
		return vmm.Share{}, err
	}
	if !filepath.IsAbs(share.Path) {
		return vmm.Share{}, fmt.Errorf("share path must be absolute (got %q)", share.Path)
	}
	share.Path, err = canonicalManagedPath(share.Path)
	if err != nil {
		return vmm.Share{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	backup := s.cfg
	backup.Shares = append([]string(nil), s.cfg.Shares...)
	backup.Ports = append([]string(nil), s.cfg.Ports...)

	seen, found := map[string]bool{}, false
	for _, raw := range s.cfg.Shares {
		existing, parseErr := vmm.ParseShareSpec(raw, seen)
		if parseErr != nil {
			return vmm.Share{}, fmt.Errorf("bad configured share %q: %w", raw, parseErr)
		}
		seen[existing.Tag] = true
		if existing.Tag == share.Tag {
			found = true
			continue
		}
		otherPath, pathErr := canonicalManagedPath(existing.Path)
		if pathErr != nil {
			return vmm.Share{}, fmt.Errorf("share %s: %w", existing.Tag, pathErr)
		}
		if pathsOverlap(share.Path, otherPath) {
			return vmm.Share{}, fmt.Errorf("share %s overlaps share %s (%s)", share.Tag, existing.Tag, otherPath)
		}
		if configuredShareTarget(share) == configuredShareTarget(existing) {
			return vmm.Share{}, fmt.Errorf("share tags %q and %q both target %s", existing.Tag, share.Tag, configuredShareTarget(share))
		}
	}
	if found && !replace {
		return vmm.Share{}, fmt.Errorf("share tag %q already exists (use replace)", share.Tag)
	}
	if !found && len(s.cfg.Shares) >= maxManagedShares {
		return vmm.Share{}, fmt.Errorf("too many shares (max %d)", maxManagedShares)
	}
	if containerPathsOverlap(configuredShareTarget(share), shares.HubInternalPath) {
		return vmm.Share{}, fmt.Errorf("share %s may not cover, sit under, or contain the internal hub path %s", share.Tag, shares.HubInternalPath)
	}

	s.cfg.Shares = shareSpecsReplacingTag(s.cfg.Shares, share.Tag, shareConfigSpec(share))
	if err := s.writeLocked(); err != nil {
		s.cfg = backup
		return vmm.Share{}, err
	}
	return share, nil
}

// RemoveShareForRestart removes a persisted share without touching a live
// hub. Stopped sandboxes use this path; a running sandbox delegates removal to
// its broker instead so the live namespace and desired configuration move as
// one transaction.
func (s *ConfigStore) RemoveShareForRestart(tag string) (vmm.Share, error) {
	if err := shares.ValidateShareTag(tag); err != nil {
		return vmm.Share{}, err
	}
	var removed vmm.Share
	err := s.Mutate(func(cfg *RunConfig) error {
		seen := map[string]bool{}
		found := false
		for _, raw := range cfg.Shares {
			share, parseErr := vmm.ParseShareSpec(raw, seen)
			if parseErr != nil {
				return fmt.Errorf("bad configured share %q: %w", raw, parseErr)
			}
			seen[share.Tag] = true
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

func configuredShareTarget(share vmm.Share) string {
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
	return writeFileAtomic(s.path, append(b, '\n'), 0o600)
}
