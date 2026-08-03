package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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

func (s *ConfigStore) writeLocked() error {
	b, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, append(b, '\n'), 0o600)
}
