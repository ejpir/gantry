package manager

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type ensureResult struct {
	Socket  string `json:"socket"`
	Version string `json:"version"`
	Started bool   `json:"started"`
	PID     int    `json:"pid,omitempty"`
}

// This check runs under the ordinary manager-state lock in the child. An
// automatic launch must never replace a configured policy-feed manager with
// an ungoverned one, even after that manager has exited. The state directory
// itself is the durable marker: NewReceiver creates it as soon as a feed is
// configured, but the first generation is only persisted after a successful
// synchronization — a feed-enabled manager whose initial sync never succeeds
// leaves an existing but empty directory, which must still refuse automatic
// replacement.
func allowAutomaticManager(stateDir string) error {
	if _, err := os.Stat(filepath.Join(stateDir, "policy-feeds")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("inspect saved manager governance: %w", err)
	}
	return errors.New("saved organization policy-feed state requires an explicit gantry serve command with its policy-feed configuration; automatic startup refused (remove the policy-feeds state directory only if the feed was intentionally retired)")
}
