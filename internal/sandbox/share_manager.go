package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"gantry/internal/shares"
	"gantry/internal/virtio"
	"gantry/internal/vmm"
)

const maxManagedShares = 256

// ShareManager owns a persistent sandbox's dynamic share namespace. The VMM
// receives the manager's hub before boot; the ctl.sock broker retains the
// manager so live mutations update the FUSE namespace, sandbox.json and the
// dashboard manifest as one control-plane transaction.
type ShareManager struct {
	dir        string
	hub        *virtio.ShareHub
	mu         sync.Mutex
	cfg        RunConfig
	exports    map[string]*managedShare
	retired    []*managedShare
	generation uint64
}

type managedShare struct {
	share     vmm.Share
	export    *virtio.ShareExport
	ephemeral bool
}

// NewShareManager prepares every configured export before vmm.Prepare. A nil
// hub (only on platforms without a virtio-fs backend) preserves the legacy
// per-device path for an empty configuration.
func NewShareManager(dir string, cfg RunConfig) (*ShareManager, []string, error) {
	m := &ShareManager{dir: dir, cfg: cfg, exports: map[string]*managedShare{}}
	if len(cfg.Shares) > maxManagedShares {
		return nil, nil, fmt.Errorf("too many shares: %d (max %d)", len(cfg.Shares), maxManagedShares)
	}
	hub, err := virtio.NewShareHub()
	if err != nil {
		if len(cfg.Shares) == 0 {
			// Platforms without a host FUSE backend can still run shareless
			// sandboxes through the legacy no-share path.
			return m, nil, nil
		}
		return nil, nil, err
	}
	m.hub = hub
	var warnings []string
	seenTags := map[string]bool{}
	for _, raw := range cfg.Shares {
		share, err := vmm.ParseShareSpec(raw, seenTags)
		if err != nil {
			m.Close()
			return nil, nil, fmt.Errorf("bad configured share %q: %w", raw, err)
		}
		seenTags[share.Tag] = true
		if share.Tag == "hostshare" && share.CtrPath == "" {
			share.CtrPath = defaultHubCtrPath(share.Tag)
			warnings = append(warnings, `share "hostshare" now appears at /host/hostshare (the hub root owns /host; use an explicit @/host alias for the legacy path)`)
		}
		if !filepath.IsAbs(share.Path) {
			m.Close()
			return nil, nil, fmt.Errorf("share %s path must be absolute (got %q)", share.Tag, share.Path)
		}
		if err := m.validateNewShare(share); err != nil {
			m.Close()
			return nil, nil, err
		}
		prepared, canonical, err := m.hub.Prepare(share.Tag, share.Path, share.RO)
		if err != nil {
			m.Close()
			return nil, nil, fmt.Errorf("share %s: %w", share.Tag, err)
		}
		export, err := m.hub.Publish(prepared)
		if err != nil {
			prepared.ClosePrepared()
			m.Close()
			return nil, nil, fmt.Errorf("share %s: %w", share.Tag, err)
		}
		share.Path = canonical
		m.exports[share.Tag] = &managedShare{share: share, export: export}
	}
	return m, warnings, nil
}

// Hub returns the device attached by vmm.Prepare. Nil means unsupported and
// shareless.
func (m *ShareManager) Hub() *virtio.ShareHub { return m.hub }

// Close releases all host-side export roots.
func (m *ShareManager) Close() error {
	if m == nil || m.hub == nil {
		return nil
	}
	return m.hub.Close()
}

func defaultHubCtrPath(tag string) string { return shares.HubHostPath + "/" + tag }

func canonicalManagedPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("not a directory: %s", resolved)
	}
	return resolved, nil
}

func pathsOverlap(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	return a == b || strings.HasPrefix(a, b+string(filepath.Separator)) || strings.HasPrefix(b, a+string(filepath.Separator))
}

func (m *ShareManager) validateNewShare(share vmm.Share) error {
	if len(m.exports) >= maxManagedShares {
		return fmt.Errorf("too many shares (max %d)", maxManagedShares)
	}
	if _, exists := m.exports[share.Tag]; exists {
		return fmt.Errorf("share tag %q already exists", share.Tag)
	}
	canonical, err := canonicalManagedPath(share.Path)
	if err != nil {
		return fmt.Errorf("share %s: %w", share.Tag, err)
	}
	ctr := share.CtrPath
	if ctr == "" {
		ctr = defaultHubCtrPath(share.Tag)
	}
	if ctr == shares.HubInternalPath {
		return fmt.Errorf("share %s may not cover the internal hub path %s", share.Tag, shares.HubInternalPath)
	}
	for _, existing := range m.exports {
		otherCanonical, err := canonicalManagedPath(existing.share.Path)
		if err == nil && pathsOverlap(canonical, otherCanonical) {
			return fmt.Errorf("share %s overlaps share %s (%s)", share.Tag, existing.share.Tag, otherCanonical)
		}
		otherCtr := existing.share.CtrPath
		if otherCtr == "" {
			otherCtr = defaultHubCtrPath(existing.share.Tag)
		}
		if ctr == otherCtr {
			return fmt.Errorf("share tags %q and %q both target %s", existing.share.Tag, share.Tag, ctr)
		}
	}
	return nil
}

// Add publishes TAG=PATH[,ro] without restarting the VM. Live additions are
// deliberately limited to the stable /host/<tag> path; arbitrary container
// aliases still require container creation.
func (m *ShareManager) Add(spec string, persistent, replace bool) (shares.Entry, error) {
	m.muLock()
	defer m.muUnlock()
	if m.hub == nil {
		return shares.Entry{}, fmt.Errorf("live shares require the virtio-fs hub (unsupported on this platform)")
	}
	share, err := vmm.ParseShareSpec(spec, map[string]bool{})
	if err != nil {
		return shares.Entry{}, err
	}
	if share.CtrPath != "" {
		return shares.Entry{}, fmt.Errorf("live shares always appear at /host/<tag>; @CTRPATH requires sandbox restart")
	}
	if !filepath.IsAbs(share.Path) {
		return shares.Entry{}, fmt.Errorf("share path must be absolute (got %q)", share.Path)
	}
	share.CtrPath = defaultHubCtrPath(share.Tag)
	if share.Tag == "hostshare" {
		// hostshare has no special /host shortcut in hub mode.
		share.CtrPath = defaultHubCtrPath(share.Tag)
	}
	var existing *managedShare
	if existing = m.exports[share.Tag]; existing != nil {
		canonical, _ := canonicalManagedPath(share.Path)
		if existing.share.Path == canonical && existing.share.RO == share.RO {
			return m.entry(existing), nil
		}
		if !replace {
			return shares.Entry{}, fmt.Errorf("share tag %q already exists with different settings (use --replace)", share.Tag)
		}
		// Validate and prepare the candidate before disturbing the old export,
		// so a bad replacement cannot remove a working share.
		delete(m.exports, share.Tag)
		err := m.validateNewShare(share)
		m.exports[share.Tag] = existing
		if err != nil {
			return shares.Entry{}, err
		}
	} else if err := m.validateNewShare(share); err != nil {
		return shares.Entry{}, err
	}
	prepared, canonical, err := m.hub.Prepare(share.Tag, share.Path, share.RO)
	if err != nil {
		return shares.Entry{}, err
	}
	if existing != nil {
		if _, err := m.removeLocked(share.Tag, persistent, true); err != nil {
			prepared.ClosePrepared()
			return shares.Entry{}, err
		}
	}
	share.Path = canonical
	ms := &managedShare{share: share, ephemeral: !persistent}
	if persistent {
		if err := m.persistAddLocked(share); err != nil {
			prepared.ClosePrepared()
			return shares.Entry{}, err
		}
	}
	export, err := m.hub.Publish(prepared)
	if err != nil {
		if persistent {
			_ = m.persistRemoveLocked(share.Tag)
		}
		prepared.ClosePrepared()
		return shares.Entry{}, err
	}
	ms.export = export
	m.exports[share.Tag] = ms
	m.generation++
	entry := m.entry(ms)
	return entry, m.publishLocked()
}

// Remove hides a share immediately. Graceful removal drains existing handles;
// force revokes subsequent host-backed operations with ESTALE.
func (m *ShareManager) Remove(tag string, persistent, force bool) (shares.Entry, error) {
	m.muLock()
	defer m.muUnlock()
	return m.removeLocked(tag, persistent, force)
}

func (m *ShareManager) removeLocked(tag string, persistent, force bool) (shares.Entry, error) {
	if m.hub == nil {
		return shares.Entry{}, fmt.Errorf("live shares require the virtio-fs hub (unsupported on this platform)")
	}
	ms := m.exports[tag]
	if ms == nil {
		return shares.Entry{}, fmt.Errorf("share tag %q not found", tag)
	}
	ctr := ms.share.CtrPath
	if ctr == "" {
		ctr = defaultHubCtrPath(tag)
	}
	if ctr != defaultHubCtrPath(tag) && !force {
		return shares.Entry{}, fmt.Errorf("share %q has an explicit container alias at %s; use --force or restart the sandbox", tag, ctr)
	}
	if persistent && !ms.ephemeral {
		if err := m.persistRemoveLocked(tag); err != nil {
			return shares.Entry{}, err
		}
	}
	export, err := m.hub.Remove(tag, force)
	if err != nil {
		if persistent && !ms.ephemeral {
			_ = m.persistAddLocked(ms.share)
		}
		return shares.Entry{}, err
	}
	delete(m.exports, tag)
	m.retired = append(m.retired, ms)
	m.generation++
	entry := m.entry(&managedShare{share: ms.share, export: export, ephemeral: ms.ephemeral})
	return entry, m.publishLocked()
}

// Generation is the live namespace version written to shares.json.
func (m *ShareManager) Generation() uint64 {
	m.muLock()
	defer m.muUnlock()
	return m.generation
}

// Entries returns the live namespace plus exports still draining after a
// removal. Stopped sandboxes use loadTUIMounts' sandbox.json fallback instead.
func (m *ShareManager) Entries() []shares.Entry {
	m.muLock()
	defer m.muUnlock()
	return m.entriesLocked()
}

func (m *ShareManager) entriesLocked() []shares.Entry {
	out := make([]shares.Entry, 0, len(m.exports)+len(m.retired))
	for _, ms := range m.exports {
		out = append(out, m.entry(ms))
	}
	kept := m.retired[:0]
	for _, ms := range m.retired {
		if ms.export != nil && ms.export.State() == virtio.ShareExportGone {
			continue
		}
		out = append(out, m.entry(ms))
		kept = append(kept, ms)
	}
	m.retired = kept
	sort.Slice(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out
}

func (m *ShareManager) entry(ms *managedShare) shares.Entry {
	ctr := ms.share.CtrPath
	if ctr == "" {
		ctr = defaultHubCtrPath(ms.share.Tag)
	}
	state := "active"
	if m.hub == nil {
		state = "saved"
	} else if ms.export != nil {
		state = ms.export.State().String()
	}
	return shares.Entry{
		Tag:     ms.share.Tag,
		Path:    ms.share.Path,
		RO:      ms.share.RO,
		VMPath:  shares.HubVMPath + "/" + ms.share.Tag,
		CtrPath: ctr,
		State:   state,
	}
}

// Publish writes the versioned live manifest consumed by the session client
// and dashboard. It is atomic and host-local; guest requests never see host
// paths over ttrpc.
func (m *ShareManager) Publish() error {
	m.muLock()
	defer m.muUnlock()
	return m.publishLocked()
}

func (m *ShareManager) publishLocked() error {
	manifest := shares.Manifest{
		Version:    shares.ManifestVersion,
		Generation: m.generation,
		Shares:     m.entriesLocked(),
	}
	if m.hub != nil {
		manifest.Transport = &shares.Transport{Tag: shares.HubTag, VMPath: shares.HubVMPath}
	}
	b, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(m.dir, "shares.json"), append(b, '\n'), 0o600)
}

func shareConfigSpec(share vmm.Share) string {
	spec := share.Tag + "=" + share.Path
	if share.CtrPath != "" && share.CtrPath != defaultHubCtrPath(share.Tag) {
		spec += "@" + share.CtrPath
	}
	if share.RO {
		spec += ",ro"
	}
	return spec
}

func (m *ShareManager) persistAddLocked(share vmm.Share) error {
	spec := shareConfigSpec(share)
	for _, existing := range m.cfg.Shares {
		if existing == spec {
			return nil
		}
	}
	old := append([]string(nil), m.cfg.Shares...)
	m.cfg.Shares = append(m.cfg.Shares, spec)
	if err := m.writeConfigLocked(); err != nil {
		m.cfg.Shares = old
		return err
	}
	return nil
}

func (m *ShareManager) persistRemoveLocked(tag string) error {
	old := append([]string(nil), m.cfg.Shares...)
	filtered := m.cfg.Shares[:0]
	for _, raw := range m.cfg.Shares {
		share, err := vmm.ParseShareSpec(raw, map[string]bool{})
		if err != nil || share.Tag != tag {
			filtered = append(filtered, raw)
		}
	}
	m.cfg.Shares = filtered
	if err := m.writeConfigLocked(); err != nil {
		m.cfg.Shares = old
		return err
	}
	return nil
}

func (m *ShareManager) writeConfigLocked() error {
	b, err := json.MarshalIndent(m.cfg, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(m.dir, "sandbox.json"), b, 0o600)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// A tiny wrapper keeps the critical section obvious at call sites (the
// manager intentionally serializes whole control-plane transactions).
func (m *ShareManager) muLock()   { m.mu.Lock() }
func (m *ShareManager) muUnlock() { m.mu.Unlock() }
