// Package inspection provides the common read model for sandbox frontends.
package inspection

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

type State string

const (
	Stopped  State = "stopped"
	Starting State = "starting"
	Running  State = "running"
)

const ActiveFile = "active.json"

// BootSettings describes settings fixed for a VM's lifetime. SSH and other
// services reconciled live deliberately do not belong to this snapshot.
type BootSettings struct {
	MemoryMiB        uint   `json:"memoryMiB"`
	CPUs             int    `json:"cpus"`
	ProcessIsolation string `json:"processIsolation"`
	DevContainers    bool   `json:"devContainers"`
}

func Settings(cfg config.RunConfig) BootSettings {
	cpus := cfg.VCPUs
	if cpus == 0 {
		cpus = 1
	}
	return BootSettings{MemoryMiB: cfg.MemMB, CPUs: cpus,
		ProcessIsolation: config.NormalizeProcessIsolation(cfg.ProcessIsolation), DevContainers: cfg.DevContainers}
}

type Snapshot struct {
	Name            string
	State           State
	PID             int
	Desired         config.RunConfig
	ConfigError     error
	Updated         time.Time
	Active          *BootSettings
	RestartRequired bool
}

// Inspect returns configuration errors as data so a damaged saved sandbox can
// still be listed and repaired. Filesystem failures remain ordinary errors.
func Inspect(name string) (Snapshot, error) {
	result := Snapshot{Name: name, State: Stopped}
	if err := layout.ValidateName(name); err != nil {
		return result, err
	}
	dir := layout.Dir(name)
	info, err := os.Stat(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		return result, err
	}
	result.Updated = info.ModTime()
	result.Desired, result.ConfigError = config.ReadSandboxConfig(dir)
	pid, alive := layout.PID(name)
	if !alive {
		if layout.LockHeld(dir) {
			result.State = Starting
		}
		return result, nil
	}
	result.PID, result.State = pid, Starting
	if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
		result.State = Running
	}
	if result.State == Running {
		raw, err := os.ReadFile(filepath.Join(dir, ActiveFile))
		if err == nil {
			var active BootSettings
			if json.Unmarshal(raw, &active) == nil {
				result.Active = &active
				result.RestartRequired = result.ConfigError == nil && active != Settings(result.Desired)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return result, err
		}
	}
	return result, nil
}

// PublishActive runs before readiness so readers never confuse desired
// restart-only settings with the resources allocated to the current VM.
func PublishActive(dir string, cfg config.RunConfig) error {
	raw, err := json.Marshal(Settings(cfg))
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(filepath.Join(dir, ActiveFile), append(raw, '\n'), 0o600)
}
