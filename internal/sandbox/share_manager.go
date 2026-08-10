package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/sharefs"
	"github.com/ejpir/gantry/internal/shares"
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
type ShareManager struct {
	dir        string
	hub        *sharefs.Hub
	store      *ConfigStore
	mu         sync.Mutex
	exports    map[string]*managedShare
	retired    []*managedShare
	generation uint64
	failed     error
	closed     bool
}

type managedShare struct {
	share     shares.Spec
	identity  sharefs.Identity
	export    *sharefs.Export
	ephemeral bool
}

// shareAddCandidate owns a pinned root until commit publishes it. Publish and
// Swap consume prepared on success; Close is therefore safe on every return
// path and makes descriptor ownership explicit.
type shareAddCandidate struct {
	share     shares.Spec
	identity  sharefs.Identity
	prepared  *sharefs.Prepared
	existing  *managedShare
	identical bool
}

func (c *shareAddCandidate) Close() {
	if c != nil {
		c.prepared.Close()
	}
}

// shareAddTransaction is the three-stage live-add transaction: persist the
// desired configuration, stage the manifest, then publish the pinned root.
// Only the final hub operation is irreversible.
type shareAddTransaction struct {
	manager    *ShareManager
	candidate  *shareAddCandidate
	addition   *managedShare
	persistent bool
	oldConfig  []string
	persistErr error
	retiredLen int
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
	hub, err := sharefs.NewHub()
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
	configured, err := shares.ParseSpecs(cfg.Shares)
	if err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("bad configured share: %w", err)
	}
	for _, share := range configured {
		if share.Tag == "hostshare" && share.CtrPath == "" {
			share.CtrPath = defaultHubCtrPath(share.Tag)
			warnings = append(warnings, `share "hostshare" now appears at /host/hostshare (the hub root owns /host; use an explicit @/host alias for the legacy path)`)
		}
		if !filepath.IsAbs(share.Path) {
			_ = m.Close()
			return nil, nil, fmt.Errorf("share %s path must be absolute (got %q)", share.Tag, share.Path)
		}
		if err := validateShareTarget(share); err != nil {
			_ = m.Close()
			return nil, nil, err
		}
		prepared, canonical, err := m.hub.PrepareMapped(share.Tag, share.Path, share.RO, share.UID, share.GID)
		if err != nil {
			_ = m.Close()
			return nil, nil, fmt.Errorf("share %s: %w", share.Tag, err)
		}
		identity := prepared.Identity()
		share.Path = canonical
		if err := m.validatePreparedShare(share, identity, nil); err != nil {
			prepared.Close()
			_ = m.Close()
			return nil, nil, err
		}
		export, err := m.hub.Publish(prepared)
		if err != nil {
			prepared.Close()
			_ = m.Close()
			return nil, nil, fmt.Errorf("share %s: %w", share.Tag, err)
		}
		m.exports[share.Tag] = &managedShare{share: share, identity: identity, export: export}
	}
	return m, warnings, nil
}

// Hub returns the trusted serving hub. Monolithic VMMs attach it directly;
// split VMMs attach a request-only proxy while this hub stays here.
func (m *ShareManager) Hub() *sharefs.Hub { return m.hub }

// Close releases all host-side export roots.
func (m *ShareManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.hub == nil {
		return nil
	}
	return m.hub.Close()
}

func (m *ShareManager) readyLocked() error {
	if m.failed != nil {
		return fmt.Errorf("share manager failed closed: %w", m.failed)
	}
	if m.closed {
		return fmt.Errorf("share manager is closed")
	}
	return nil
}

// failLocked makes an ambiguous control-plane transaction fail closed. Once
// config or manifest rollback fails, serving the old namespace would claim a
// consistency guarantee the daemon can no longer prove.
func (m *ShareManager) failLocked(err error) error {
	closeErr := error(nil)
	if m.hub != nil {
		closeErr = m.hub.Close()
	}
	m.closed = true
	m.failed = errors.Join(m.failed, err, closeErr)
	return fmt.Errorf("share manager failed closed: %w", m.failed)
}

// ConfigureRestart serializes a restart-only OCI alias update with live share
// transactions. The ConfigStore protects individual writes; this manager lock
// additionally prevents Add/Remove rollback from restoring a snapshot taken
// before a concurrent configure committed.
func (m *ShareManager) ConfigureRestart(spec string, replace bool) (shares.Spec, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.readyLocked(); err != nil {
		return shares.Spec{}, err
	}
	return m.store.SetShareForRestart(spec, replace)
}

func defaultHubCtrPath(tag string) string { return shares.HubHostPath + "/" + tag }

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

func validateShareTarget(share shares.Spec) error {
	ctr := share.CtrPath
	if ctr == "" {
		ctr = defaultHubCtrPath(share.Tag)
	}
	if containerPathsOverlap(ctr, shares.HubInternalPath) {
		return fmt.Errorf("share %s may not cover, sit under, or contain the internal hub path %s", share.Tag, shares.HubInternalPath)
	}
	return nil
}

// validatePreparedShare compares only identities derived from pinned roots.
// except is the export being atomically replaced, if any.
func (m *ShareManager) validatePreparedShare(share shares.Spec, identity sharefs.Identity, except *managedShare) error {
	ctr := configuredShareTarget(share)
	for _, existing := range m.exports {
		if existing == except {
			continue
		}
		if existing.share.Tag == share.Tag {
			return fmt.Errorf("share tag %q already exists", share.Tag)
		}
		if identity.Aliases(existing.identity) {
			return fmt.Errorf("share %s aliases share %s (%s)", share.Tag, existing.share.Tag, existing.share.Path)
		}
		if identity.Overlaps(existing.identity) {
			return fmt.Errorf("share %s overlaps share %s (%s)", share.Tag, existing.share.Tag, existing.share.Path)
		}
		if ctr == configuredShareTarget(existing.share) {
			return fmt.Errorf("share tags %q and %q both target %s", existing.share.Tag, share.Tag, ctr)
		}
	}
	return nil
}

// Add publishes TAG=PATH[,ro] without restarting the VM. Live additions are
// deliberately limited to the stable /host/<tag> path; arbitrary container
// aliases still require container creation.
func (m *ShareManager) Add(spec string, persistent, replace bool) (shares.Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireLiveAddLocked(); err != nil {
		return shares.Entry{}, err
	}
	candidate, err := m.prepareAddLocked(spec, replace)
	if err != nil {
		return shares.Entry{}, err
	}
	if candidate.identical {
		candidate.Close()
		return m.completeIdenticalAddLocked(candidate.existing, persistent)
	}
	tx := shareAddTransaction{
		manager:    m,
		candidate:  candidate,
		addition:   &managedShare{share: candidate.share, identity: candidate.identity, ephemeral: !persistent},
		persistent: persistent,
	}
	return tx.commit()
}

func (m *ShareManager) requireLiveAddLocked() error {
	if err := m.readyLocked(); err != nil {
		return err
	}
	if m.hub == nil {
		// No serving backend: a platform without a virtio-fs hub.
		return fmt.Errorf("live shares require the virtio-fs hub (unsupported on this platform)")
	}
	if !m.store.Snapshot().RW {
		// A read-only container root cannot create the /host bind target,
		// so the hub was never mounted into the container (client.go).
		return fmt.Errorf("live shares require a writable container root (sandbox started with -rw=false)")
	}
	return nil
}

func (m *ShareManager) prepareAddLocked(spec string, replace bool) (*shareAddCandidate, error) {
	share, err := shares.ParseSpec(spec)
	if err != nil {
		return nil, err
	}
	if share.CtrPath != "" {
		return nil, fmt.Errorf("live shares always appear at /host/<tag>; @CTRPATH requires sandbox restart")
	}
	if !filepath.IsAbs(share.Path) {
		return nil, fmt.Errorf("share path must be absolute (got %q)", share.Path)
	}
	share.CtrPath = defaultHubCtrPath(share.Tag)
	if err := validateShareTarget(share); err != nil {
		return nil, err
	}
	existing := m.exports[share.Tag]
	if existing == nil && len(m.exports) >= maxManagedShares {
		return nil, fmt.Errorf("too many shares (max %d)", maxManagedShares)
	}
	prepared, canonical, err := m.hub.PrepareMapped(share.Tag, share.Path, share.RO, share.UID, share.GID)
	if err != nil {
		return nil, err
	}
	identity := prepared.Identity()
	share.Path = canonical
	identical := existing != nil &&
		identity.Aliases(existing.identity) &&
		existing.share.RO == share.RO &&
		shareOwnerEqual(existing.share, share)
	candidate := &shareAddCandidate{
		share:     share,
		identity:  identity,
		prepared:  prepared,
		existing:  existing,
		identical: identical,
	}
	if identical {
		return candidate, nil
	}
	if existing != nil && !replace {
		candidate.Close()
		return nil, fmt.Errorf("share tag %q already exists with different settings (use --replace)", share.Tag)
	}
	if err := m.validatePreparedShare(share, identity, existing); err != nil {
		candidate.Close()
		return nil, err
	}
	return candidate, nil
}

func (m *ShareManager) completeIdenticalAddLocked(existing *managedShare, persistent bool) (shares.Entry, error) {
	// Re-adding an ephemeral share with --persist promotes it instead of
	// taking the otherwise idempotent no-op path.
	if !persistent || !existing.ephemeral {
		return m.entry(existing), nil
	}
	var oldConfig []string
	persistErr := m.mutateSharesSnapshotLocked(existing.share.Tag, shareConfigSpec(existing.share), &oldConfig)
	if persistErr != nil && !atomicfile.Committed(persistErr) {
		return shares.Entry{}, persistErr
	}
	existing.ephemeral = false
	m.generation++
	if err := m.publishLocked(); err != nil {
		existing.ephemeral = true
		m.generation++
		recoveryErr := m.recoverControlPlaneLocked(true, oldConfig)
		return shares.Entry{}, errors.Join(err, recoveryErr)
	}
	entry := m.entry(existing)
	if persistErr != nil {
		return entry, fmt.Errorf("share promotion committed but configuration durability is uncertain: %w", persistErr)
	}
	return entry, nil
}

func (tx *shareAddTransaction) commit() (shares.Entry, error) {
	defer tx.candidate.Close()
	if err := tx.persist(); err != nil {
		return shares.Entry{}, err
	}
	tx.stage()
	if err := tx.manager.publishLocked(); err != nil {
		return tx.rollback(err)
	}
	if err := tx.publish(); err != nil {
		return tx.rollback(err)
	}
	entry := tx.manager.entry(tx.addition)
	if err := tx.manager.publishLocked(); err != nil {
		return entry, tx.manager.failLocked(fmt.Errorf("publish committed share manifest: %w", err))
	}
	if tx.persistErr != nil {
		return entry, fmt.Errorf("share added but configuration durability is uncertain: %w", tx.persistErr)
	}
	return entry, nil
}

func (tx *shareAddTransaction) persist() error {
	if !tx.persistent {
		return nil
	}
	// A replacement is one slice swap, never a remove then add sequence
	// that a crash could split.
	tx.persistErr = tx.manager.mutateSharesSnapshotLocked(
		tx.addition.share.Tag,
		shareConfigSpec(tx.addition.share),
		&tx.oldConfig,
	)
	if tx.persistErr != nil && !atomicfile.Committed(tx.persistErr) {
		return tx.persistErr
	}
	return nil
}

func (tx *shareAddTransaction) stage() {
	m := tx.manager
	tx.retiredLen = len(m.retired)
	m.exports[tx.addition.share.Tag] = tx.addition
	if tx.candidate.existing != nil {
		m.retired = append(m.retired, tx.candidate.existing)
	}
	m.generation++
}

func (tx *shareAddTransaction) publish() error {
	m := tx.manager
	var (
		export *sharefs.Export
		err    error
	)
	if tx.candidate.existing == nil {
		export, err = m.hub.Publish(tx.candidate.prepared)
	} else {
		_, export, err = m.hub.Swap(tx.candidate.prepared)
	}
	if err == nil {
		tx.addition.export = export
	}
	return err
}

func (tx *shareAddTransaction) rollback(cause error) (shares.Entry, error) {
	m := tx.manager
	tag := tx.addition.share.Tag
	delete(m.exports, tag)
	m.retired = m.retired[:tx.retiredLen]
	if tx.candidate.existing != nil {
		m.exports[tag] = tx.candidate.existing
	}
	m.generation++
	tx.candidate.Close()
	recoveryErr := m.recoverControlPlaneLocked(tx.persistent, tx.oldConfig)
	return shares.Entry{}, errors.Join(cause, recoveryErr)
}

func shareOwnerEqual(a, b shares.Spec) bool {
	if (a.UID == nil) != (b.UID == nil) || (a.GID == nil) != (b.GID == nil) {
		return false
	}
	return (a.UID == nil || *a.UID == *b.UID) && (a.GID == nil || *a.GID == *b.GID)
}

// Remove hides a share immediately. Graceful removal drains existing handles;
// force revokes subsequent host-backed operations with ESTALE.
func (m *ShareManager) Remove(tag string, persistent, force bool) (shares.Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.removeLocked(tag, persistent, force)
}

func (m *ShareManager) removeLocked(tag string, persistent, force bool) (shares.Entry, error) {
	if err := m.readyLocked(); err != nil {
		return shares.Entry{}, err
	}
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
	var oldConfig []string
	var persistErr error
	if persistent && !ms.ephemeral {
		persistErr = m.mutateSharesSnapshotLocked(tag, "", &oldConfig)
		if persistErr != nil && !atomicfile.Committed(persistErr) {
			return shares.Entry{}, persistErr
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
		recoveryErr := m.recoverControlPlaneLocked(persistent && !ms.ephemeral, oldConfig)
		return shares.Entry{}, errors.Join(err, recoveryErr)
	}
	if err := m.publishLocked(); err != nil {
		return rollback(err)
	}
	export, err := m.hub.Remove(tag, force)
	if err != nil {
		return rollback(err)
	}
	ms.export = export
	entry := m.entry(ms)
	if err := m.publishLocked(); err != nil {
		return entry, m.failLocked(fmt.Errorf("publish committed share manifest: %w", err))
	}
	if persistErr != nil {
		return entry, fmt.Errorf("share removed but configuration durability is uncertain: %w", persistErr)
	}
	return entry, nil
}

// Generation is the live namespace version written to shares.json.
func (m *ShareManager) Generation() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generation
}

// Entries returns the live namespace plus exports still draining after a
// removal. Stopped sandboxes use loadTUIMounts' sandbox.json fallback instead.
func (m *ShareManager) Entries() []shares.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.entriesLocked()
}

func (m *ShareManager) entriesLocked() []shares.Entry {
	out := make([]shares.Entry, 0, len(m.exports)+len(m.retired))
	for _, ms := range m.exports {
		out = append(out, m.entry(ms))
	}
	kept := m.retired[:0]
	for _, ms := range m.retired {
		if ms.export != nil && ms.export.State() == sharefs.ExportGone {
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
	} else if m.hub == nil {
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.readyLocked(); err != nil {
		return err
	}
	return m.publishLocked()
}

func (m *ShareManager) publishLocked() error {
	manifest := shares.Manifest{
		Version:    shares.ManifestVersion,
		Generation: m.generation,
		Shares:     m.entriesLocked(),
	}
	if m.hub != nil {
		// The same hub is attached directly in monolithic mode and served
		// through the bounded relay in split mode.
		manifest.Transport = &shares.Transport{Tag: shares.HubTag, VMPath: shares.HubVMPath}
	}
	b, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	// The manifest is derived from sandbox.json and the live hub, and is
	// regenerated at boot. Atomic visibility matters; forcing it to stable
	// storage would only add file and directory fsyncs to startup.
	return atomicfile.WriteFile(filepath.Join(m.dir, "shares.json"), append(b, '\n'), 0o600)
}

func shareConfigSpec(share shares.Spec) string {
	// The persistent hub's implicit target is /host/<tag>. Keep omitting that
	// derived value from sandbox.json while delegating canonical formatting to
	// the share model.
	if share.CtrPath == defaultHubCtrPath(share.Tag) {
		share.CtrPath = ""
	}
	return share.String()
}

// shareSpecsReplacingTag returns specs with every entry for tag dropped and
// newSpec appended ("" = removal only). One slice, one write — replacing a
// share never takes the remove-then-add path that a crash could split.
func shareSpecsReplacingTag(specs []string, tag, newSpec string) []string {
	out := make([]string, 0, len(specs)+1)
	for _, raw := range specs {
		share, err := shares.ParseSpec(raw)
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

func (m *ShareManager) restoreSharesLocked(old []string) error {
	return m.store.Mutate(func(cfg *RunConfig) error {
		cfg.Shares = append([]string(nil), old...)
		return nil
	})
}

// recoverControlPlaneLocked restores the pre-transaction persistent and
// manifest state. Any recovery failure closes the hub: continuing to serve
// after that point would make disk, dashboard, and live namespace disagree.
func (m *ShareManager) recoverControlPlaneLocked(restoreConfig bool, oldConfig []string) error {
	var recoveryErr error
	if restoreConfig {
		if err := m.restoreSharesLocked(oldConfig); err != nil {
			recoveryErr = errors.Join(recoveryErr, fmt.Errorf("restore sandbox share configuration: %w", err))
		}
	}
	if err := m.publishLocked(); err != nil {
		recoveryErr = errors.Join(recoveryErr, fmt.Errorf("restore share manifest: %w", err))
	}
	if recoveryErr != nil {
		return m.failLocked(recoveryErr)
	}
	return nil
}
