package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/ejpir/gantry/internal/shares"
	"github.com/ejpir/gantry/internal/virtio"
	"github.com/ejpir/gantry/internal/vmm"
)

const maxManagedShares = 256

// ShareManager owns a persistent sandbox's dynamic share namespace. The VMM
// receives the manager's hub before boot; the ctl.sock broker retains the
// manager so live mutations update the FUSE namespace, sandbox.json and the
// dashboard manifest as one control-plane transaction.
//
// Transaction order is crash-atomic: the persisted configuration is updated
// first (a single ConfigStore mutation computing the final Shares slice),
// the manifest is published second, and only then is the live namespace
// touched. Every step before the hub mutation is reversible, so a failure
// anywhere rolls all three back; a crash anywhere leaves on-disk state the
// next boot can either replay (config) or regenerate (manifest).
// shareServing is the share-plane backend behind ShareManager: the
// FUSE-serving hub lives either in this process (monolithic) or in the
// _vmm-worker (split VMM), driven over RPC with descriptor transfers.
// "prepared" tokens are opaque staging handles (a *virtio.PreparedShare
// locally, an RPC token remotely).
type shareServing interface {
	PrepareMapped(tag, path string, ro bool, uid, gid *uint32) (prepared any, canonical string, err error)
	Publish(prepared any) (*virtio.ShareExport, error)
	Swap(prepared any) (old, exp *virtio.ShareExport, err error)
	Remove(tag string, force bool) (*virtio.ShareExport, error)
	ClosePrepared(prepared any)
	Close() error
}

// localShareServing adapts the in-process hub.
type localShareServing struct{ hub *virtio.ShareHub }

func (s localShareServing) PrepareMapped(tag, path string, ro bool, uid, gid *uint32) (any, string, error) {
	return s.hub.PrepareMapped(tag, path, ro, uid, gid)
}
func (s localShareServing) Publish(p any) (*virtio.ShareExport, error) {
	return s.hub.Publish(p.(*virtio.PreparedShare))
}
func (s localShareServing) Swap(p any) (old, exp *virtio.ShareExport, err error) {
	return s.hub.Swap(p.(*virtio.PreparedShare))
}
func (s localShareServing) Remove(tag string, force bool) (*virtio.ShareExport, error) {
	return s.hub.Remove(tag, force)
}
func (s localShareServing) ClosePrepared(p any) { p.(*virtio.PreparedShare).ClosePrepared() }
func (s localShareServing) Close() error        { return s.hub.Close() }

type ShareManager struct {
	dir        string
	hub        *virtio.ShareHub // nil when the hub lives in the vmm worker
	serving    shareServing
	store      *ConfigStore
	mu         sync.Mutex
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
// per-device path for an empty configuration. The store is the broker-owned
// configuration owner; boot state is read from its snapshot.
func NewShareManager(dir string, store *ConfigStore) (*ShareManager, []string, error) {
	cfg := store.Snapshot()
	m := &ShareManager{dir: dir, store: store, exports: map[string]*managedShare{}}
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
	m.serving = localShareServing{hub: hub}
	var warnings []string
	seenTags := map[string]bool{}
	for _, raw := range cfg.Shares {
		share, err := vmm.ParseShareSpec(raw, seenTags)
		if err != nil {
			_ = m.Close()
			return nil, nil, fmt.Errorf("bad configured share %q: %w", raw, err)
		}
		seenTags[share.Tag] = true
		if share.Tag == "hostshare" && share.CtrPath == "" {
			share.CtrPath = defaultHubCtrPath(share.Tag)
			warnings = append(warnings, `share "hostshare" now appears at /host/hostshare (the hub root owns /host; use an explicit @/host alias for the legacy path)`)
		}
		if !filepath.IsAbs(share.Path) {
			_ = m.Close()
			return nil, nil, fmt.Errorf("share %s path must be absolute (got %q)", share.Tag, share.Path)
		}
		if err := m.validateNewShare(share); err != nil {
			_ = m.Close()
			return nil, nil, err
		}
		prepared, canonical, err := m.serving.PrepareMapped(share.Tag, share.Path, share.RO, share.UID, share.GID)
		if err != nil {
			_ = m.Close()
			return nil, nil, fmt.Errorf("share %s: %w", share.Tag, err)
		}
		export, err := m.serving.Publish(prepared)
		if err != nil {
			m.serving.ClosePrepared(prepared)
			_ = m.Close()
			return nil, nil, fmt.Errorf("share %s: %w", share.Tag, err)
		}
		share.Path = canonical
		m.exports[share.Tag] = &managedShare{share: share, export: export}
	}
	return m, warnings, nil
}

// Hub returns the device attached by vmm.Prepare. Nil means unsupported,
// shareless, or worker-hosted (split VMM).
func (m *ShareManager) Hub() *virtio.ShareHub { return m.hub }

// Close releases all host-side export roots.
func (m *ShareManager) Close() error {
	if m == nil || m.serving == nil {
		return nil
	}
	return m.serving.Close()
}

// DetachServing drops the in-process hub for split-VMM mode: the serving
// hub is built in the worker from transferred roots, and SetServing
// installs the RPC backend after spawn. Boot-time bookkeeping (exports
// map, canonical paths) stays valid — the mirror exports report state.
func (m *ShareManager) DetachServing() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hub = nil
	m.serving = nil
}

// SetServing installs the post-spawn share backend (split VMM: the
// worker-hosted hub over RPC).
func (m *ShareManager) SetServing(serving shareServing) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.serving = serving
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

// containerPathsOverlap is pathsOverlap for guest container paths: always
// slash-separated regardless of the host OS, so it must not go through
// filepath.Clean on Windows. Equal, ancestor, and descendant targets all
// overlap — a bind-mount at any of those shadows (or is shadowed by) the
// hub FUSE mount depending on mount order.
func containerPathsOverlap(a, b string) bool {
	a = path.Clean(a)
	b = path.Clean(b)
	if a == b || a == "/" || b == "/" {
		// the root contains every target
		return true
	}
	return strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
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
	if containerPathsOverlap(ctr, shares.HubInternalPath) {
		return fmt.Errorf("share %s may not cover, sit under, or contain the internal hub path %s", share.Tag, shares.HubInternalPath)
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
	if m.serving == nil {
		// No serving backend: a platform without a virtio-fs hub. After a
		// VMM split m.hub is nil BY DESIGN (the hub lives in the worker);
		// the RPC serving backend is what matters here.
		return shares.Entry{}, fmt.Errorf("live shares require the virtio-fs hub (unsupported on this platform)")
	}
	if !m.store.Snapshot().RW {
		// A read-only container root cannot create the /host bind target,
		// so the hub was never mounted into the container (client.go).
		return shares.Entry{}, fmt.Errorf("live shares require a writable container root (sandbox started with -rw=false)")
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
		if existing.share.Path == canonical && existing.share.RO == share.RO && shareOwnerEqual(existing.share, share) {
			// Identical share: re-adding an ephemeral share with --persist
			// promotes it to persistent instead of being a no-op.
			if persistent && existing.ephemeral {
				if err := m.mutateSharesLocked(share.Tag, shareConfigSpec(existing.share)); err != nil {
					return shares.Entry{}, err
				}
				existing.ephemeral = false
				m.generation++
				return m.entry(existing), m.publishLocked()
			}
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
	if m.serving == nil {
		return shares.Entry{}, fmt.Errorf("share backend unavailable")
	}
	prepared, canonical, err := m.serving.PrepareMapped(share.Tag, share.Path, share.RO, share.UID, share.GID)
	if err != nil {
		return shares.Entry{}, err
	}
	share.Path = canonical
	ms := &managedShare{share: share, ephemeral: !persistent}

	// Persist first: one mutation computing the final Shares slice (an
	// atomic replace for an existing tag — never separate remove+add
	// writes). Then stage memory + manifest, and touch the live namespace
	// last; failures before the hub mutation roll everything back.
	var oldConfig []string
	if persistent {
		// Replacing an existing persistent share is still a single
		// slice swap: shareSpecsReplacingTag drops the tag's old
		// specs and appends the new one in one write.
		if err := m.mutateSharesSnapshotLocked(share.Tag, shareConfigSpec(share), &oldConfig); err != nil {
			m.serving.ClosePrepared(prepared)
			return shares.Entry{}, err
		}
	}
	retiredIdx := len(m.retired)
	m.exports[share.Tag] = ms
	if existing != nil {
		m.retired = append(m.retired, existing)
	}
	m.generation++
	rollback := func(err error) (shares.Entry, error) {
		delete(m.exports, share.Tag)
		m.retired = m.retired[:retiredIdx]
		if existing != nil {
			m.exports[share.Tag] = existing
		}
		m.generation++
		if persistent {
			m.restoreSharesLocked(oldConfig)
		}
		_ = m.publishLocked()
		m.serving.ClosePrepared(prepared)
		return shares.Entry{}, err
	}
	if err := m.publishLocked(); err != nil {
		return rollback(err)
	}
	var export *virtio.ShareExport
	if existing != nil {
		_, export, err = m.serving.Swap(prepared)
	} else {
		export, err = m.serving.Publish(prepared)
	}
	if err != nil {
		return rollback(err)
	}
	ms.export = export
	// Best-effort refresh: the pre-swap publish validated writability and
	// the rollback path republishes on failure; this one just tightens the
	// retired/active states now that the live namespace has moved. A stale
	// manifest self-heals on the next mutation or boot Publish.
	_ = m.publishLocked()
	return m.entry(ms), nil
}

func shareOwnerEqual(a, b vmm.Share) bool {
	if (a.UID == nil) != (b.UID == nil) || (a.GID == nil) != (b.GID == nil) {
		return false
	}
	return (a.UID == nil || *a.UID == *b.UID) && (a.GID == nil || *a.GID == *b.GID)
}

// Remove hides a share immediately. Graceful removal drains existing handles;
// force revokes subsequent host-backed operations with ESTALE.
func (m *ShareManager) Remove(tag string, persistent, force bool) (shares.Entry, error) {
	m.muLock()
	defer m.muUnlock()
	return m.removeLocked(tag, persistent, force)
}

func (m *ShareManager) removeLocked(tag string, persistent, force bool) (shares.Entry, error) {
	if m.serving == nil {
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
	var oldConfig []string
	if persistent && !ms.ephemeral {
		if err := m.mutateSharesSnapshotLocked(tag, "", &oldConfig); err != nil {
			return shares.Entry{}, err
		}
	}
	// Unstage + manifest before revoking the live export, so a failure
	// anywhere leaves config, manifest and live state consistent.
	retiredIdx := len(m.retired)
	delete(m.exports, tag)
	m.retired = append(m.retired, ms)
	m.generation++
	rollback := func(err error) (shares.Entry, error) {
		m.retired = m.retired[:retiredIdx]
		m.exports[tag] = ms
		m.generation++
		if persistent && !ms.ephemeral {
			m.restoreSharesLocked(oldConfig)
		}
		_ = m.publishLocked()
		return shares.Entry{}, err
	}
	if err := m.publishLocked(); err != nil {
		return rollback(err)
	}
	export, err := m.serving.Remove(tag, force)
	if err != nil {
		return rollback(err)
	}
	ms.export = export
	_ = m.publishLocked() // refresh export states post-revoke; see Add
	return m.entry(ms), nil
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
	if ms.export != nil {
		state = ms.export.State().String()
	} else if m.hub == nil && m.serving == nil {
		state = "saved"
	}
	return shares.Entry{
		Tag:     ms.share.Tag,
		Path:    ms.share.Path,
		RO:      ms.share.RO,
		UID:     ms.share.UID,
		GID:     ms.share.GID,
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
	if m.hub != nil || m.serving != nil {
		// The hub transport exists in both topologies: locally (m.hub)
		// or in the vmm worker (m.serving after the split).
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
	if share.UID != nil {
		spec += fmt.Sprintf(",uid=%d,gid=%d", *share.UID, *share.GID)
	}
	return spec
}

// shareSpecsReplacingTag returns specs with every entry for tag dropped and
// newSpec appended ("" = removal only). One slice, one write — replacing a
// share never takes the remove-then-add path that a crash could split.
func shareSpecsReplacingTag(specs []string, tag, newSpec string) []string {
	out := make([]string, 0, len(specs)+1)
	for _, raw := range specs {
		share, err := vmm.ParseShareSpec(raw, map[string]bool{})
		if err != nil || share.Tag != tag {
			out = append(out, raw)
		}
	}
	if newSpec != "" {
		out = append(out, newSpec)
	}
	return out
}

// mutateSharesSnapshotLocked persists the tag replacement through the
// ConfigStore and returns the previous Shares slice for rollback. The
// replacement is computed INSIDE the Mutate callback, which runs under
// the store lock: the read-modify-write is then atomic against every
// other cfg.Shares writer (SetShareForRestart, resources, netpol).
// Computing from a pre-Mutate Snapshot would let a concurrent configure
// commit in between and be silently overwritten by a stale final slice.
func (m *ShareManager) mutateSharesSnapshotLocked(tag, newSpec string, old *[]string) error {
	return m.store.Mutate(func(cfg *RunConfig) error {
		*old = append([]string(nil), cfg.Shares...)
		cfg.Shares = shareSpecsReplacingTag(cfg.Shares, tag, newSpec)
		return nil
	})
}

// mutateSharesLocked is the no-rollback-needed variant (promotion path).
func (m *ShareManager) mutateSharesLocked(tag, newSpec string) error {
	return m.store.Mutate(func(cfg *RunConfig) error {
		cfg.Shares = shareSpecsReplacingTag(cfg.Shares, tag, newSpec)
		return nil
	})
}

func (m *ShareManager) restoreSharesLocked(old []string) {
	_ = m.store.Mutate(func(cfg *RunConfig) error {
		cfg.Shares = append([]string(nil), old...)
		return nil
	})
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
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
