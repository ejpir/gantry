package manager

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const ensureTimeout = 8 * time.Second

var errManagerAbsent = errors.New("local manager is not listening")
var errManagerNotPrivate = errors.New("manager path must have owner-only permissions")

type ensureResult struct {
	Socket  string `json:"socket"`
	Version string `json:"version"`
	Started bool   `json:"started"`
	PID     int    `json:"pid,omitempty"`
}

// This check runs under the ordinary manager-state lock in the child. An
// automatic launch must never replace a configured policy-feed manager with
// an ungoverned one, even after that manager has exited.
func allowAutomaticManager(stateDir string) error {
	entries, err := os.ReadDir(filepath.Join(stateDir, "policy-feeds"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect saved manager governance: %w", err)
	}
	if len(entries) != 0 {
		return errors.New("saved organization policy-feed state requires an explicit gantry serve command with its policy-feed configuration; automatic startup refused")
	}
	return nil
}
