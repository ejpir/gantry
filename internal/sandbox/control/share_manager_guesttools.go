package control

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/shares"
)

const (
	GuestToolsMaxBytes = 64 << 20
	guestToolsShareTag = "gantry-tools"
)

// WithGuestToolsShare delivers daemon-provisioned helper bytes, not access to
// a host directory selected by a user. It deliberately accepts no host path,
// share options, or policy-bypass flag and is not exposed by the control RPC.
// The only export is a fresh private directory containing gantry-guest, pinned
// read-only, ephemeral, and revoked before the staging directory is removed.
// Organization mount rules apply to every ordinary Add (including this tag).
// State/source isolation, overlap checks, and the hub's policy expiry remain
// authoritative for this infrastructure export too.
func (m *ShareManager) WithGuestToolsShare(ctx context.Context, data []byte, use func(shares.Entry) error) error {
	if len(data) == 0 || len(data) > GuestToolsMaxBytes {
		return fmt.Errorf("guest-tools payload must contain 1..%d bytes", GuestToolsMaxBytes)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	stageBase := guestToolsStageBase(runtime.GOOS, m.dir)
	if runtime.GOOS == "windows" {
		if stageBase == "" {
			return fmt.Errorf("sandbox state directory unavailable for guest-tools staging")
		}
		if err := localsec.CreateManagerDir(stageBase); err != nil {
			return fmt.Errorf("secure guest-tools staging root: %w", err)
		}
	}
	return withGuestToolsStage(stageBase, data, func(stageDir string) (resultErr error) {
		if err := ctx.Err(); err != nil {
			return err
		}
		entry, owned, err := m.addGuestToolsShare(stageDir)
		if err != nil {
			return fmt.Errorf("share hot-add: %w", err)
		}
		defer func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			// Ordinary mutations cannot replace/remove this export. Still check
			// ownership so cleanup can never revoke an unrelated replacement.
			var cleanupErr error
			if m.exports[guestToolsShareTag] != owned {
				cleanupErr = fmt.Errorf("guest-tools share ownership changed")
			} else {
				_, cleanupErr = m.removeLocked(guestToolsShareTag, false, true)
			}
			if cleanupErr != nil && !m.closed {
				cleanupErr = m.failLocked(fmt.Errorf("guest-tools share cleanup: %w", cleanupErr))
			}
			resultErr = errors.Join(resultErr, cleanupErr)
		}()
		return use(entry)
	})
}

func (m *ShareManager) addGuestToolsShare(stageDir string) (shares.Entry, *managedShare, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireLiveAddLocked(); err != nil {
		return shares.Entry{}, nil, err
	}
	if deadline := m.governance.ExpiresAt(); !deadline.IsZero() && !time.Now().Before(deadline) {
		return shares.Entry{}, nil, fmt.Errorf("organization policy expired")
	}
	// Only WithGuestToolsShare calls this with its newly staged payload. Never
	// replace a user export, even when it happens to use the helper's tag.
	candidate, err := m.preparePinnedAddLocked(shares.Spec{
		Tag: guestToolsShareTag, Path: stageDir, RO: true,
		CtrPath: config.DefaultHubCtrPath(guestToolsShareTag),
	}, false)
	if err != nil {
		return shares.Entry{}, nil, err
	}
	addition := &managedShare{
		share: candidate.share, identity: candidate.identity,
		ephemeral: true, internal: true,
	}
	tx := shareAddTransaction{manager: m, candidate: candidate, addition: addition}
	entry, err := tx.commit()
	return entry, addition, err
}

// withGuestToolsStage owns one attempt's temporary payload. Cleanup is local
// rather than deferred to daemon shutdown, so retries cannot overwrite or
// accumulate staging-directory state.
func withGuestToolsStage(base string, data []byte, use func(string) error) (resultErr error) {
	stageDir, err := os.MkdirTemp(base, "gantry-guest-tools-*")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(stageDir)) }()
	if err := os.WriteFile(filepath.Join(stageDir, "gantry-guest"), data, 0o755); err != nil {
		return err
	}
	return use(stageDir)
}

// guestToolsStageBase keeps Windows staging in a private sibling of the
// protected Gantry state tree. Staging inside that tree would overlap protected
// state; ordinary Windows temp may be inaccessible to service launches.
// An empty base deliberately selects OS temp on Unix.
func guestToolsStageBase(goos, sandboxDir string) string {
	if goos == "windows" {
		if sandboxDir == "" {
			return ""
		}
		return layout.ProtectionRoot(sandboxDir) + "-guest-tools"
	}
	return ""
}
