package sandbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/guestasset"
	"github.com/ejpir/gantry/internal/shares"
)

// Guest-tools delivery: sandboxes configured with host-bound secrets
// (-secret NAME@host) need the multicall helper inside the guest. Two
// channels, in preference order:
//
//  1. share hot-add — the daemon stages the binary in a sandbox-local
//     directory, live-adds it as a read-only share, and a short guest
//     command copies it into /run/gantry/bin. The virtio-fs path is built
//     for bulk file data; the exec channel is not.
//  2. exec-channel fallback (no virtio-fs hub, or -rw=false) — base64
//     through the session stdin pipe. Small commands only: bulk transfer
//     over this channel risks truncation under load.
//
// Both paths end with a guest-side sha256+size verification before
// broker.guestToolsReady flips: a mangled helper must never become an
// executable the guest trusts. Delivery failure is a loud warning, not a
// boot failure: ambient secrets still work, bound ones are unusable that
// boot and the warning says so.
const (
	guestToolsMaxBytes  = 64 << 20
	guestToolsDirGuest  = "/run/gantry/bin"
	guestToolsShareTag  = "gantry-tools"
	guestToolsShareDir  = "guesttools"
	guestToolsDeliverOp = "guest tools delivery"
	guestToolsVerifyOp  = "guest tools verify"
	guestToolsTimeout   = 120 * time.Second
)

// hasBoundSecrets reports whether any persisted secret name carries a host
// binding ("NAME@host").
func hasBoundSecrets(names []string) bool {
	for _, name := range names {
		if strings.ContainsRune(name, '@') {
			return true
		}
	}
	return false
}

// deliverGuestTools stages and installs gantry-guest when the sandbox has
// bound secrets. It runs concurrently with readiness publication — never
// on the boot path — and flips broker.guestToolsReady when the helper is
// in place; sessions started after that point get the git wiring.
func (d *daemonRuntime) deliverGuestTools() {
	if d.broker == nil || !hasBoundSecrets(d.store.Snapshot().SecretNames) {
		return
	}
	progress := func(format string, a ...any) { fmt.Fprintf(os.Stderr, "daemon: "+format+"\n", a...) }
	// The CLI persists the path it resolved (dev tree, release cache, or
	// GANTRY_ARTIFACTS); fall back to the default for configs written
	// before this field existed.
	assetPath := d.cfg.GuestTools
	if assetPath == "" {
		assetPath = guestasset.DefaultGuestTools()
	}
	path, err := guestasset.EnsureGuestTools(assetPath, progress)
	if err != nil {
		d.guestToolsFailed("guest tools unavailable: %v", err)
		return
	}
	data, err := readCapped(path, guestToolsMaxBytes)
	if err != nil {
		d.guestToolsFailed("read guest tools: %v", err)
		return
	}
	sum := sha256.Sum256(data)

	if err := d.deliverGuestToolsViaShare(data, sum); err == nil {
		d.broker.guestToolsReady.Store(true)
		fmt.Fprintln(os.Stderr, "daemon: guest tools delivered via share (credential helper for bound secrets)")
		return
	} else {
		fmt.Fprintf(os.Stderr, "daemon: share delivery unavailable (%v); trying exec channel\n", err)
	}
	if err := d.deliverGuestToolsViaExec(data, sum); err == nil {
		d.broker.guestToolsReady.Store(true)
		fmt.Fprintln(os.Stderr, "daemon: guest tools delivered via exec channel (credential helper for bound secrets)")
		return
	} else {
		d.guestToolsFailed("exec-channel delivery: %v", err)
	}
}

func (d *daemonRuntime) guestToolsFailed(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "daemon: WARNING: "+format+"\n", a...)
	fmt.Fprintln(os.Stderr, "daemon: bound secrets will NOT be usable in the guest this boot")
	// Remove whatever landed: a stale or corrupt helper must not be
	// executable (earlier boots may have left one in a persistent layer).
	_, _, _ = d.broker.internalExec(strings.NewReader(""), []string{"sh", "-c",
		fmt.Sprintf("rm -rf %[1]s", guestToolsDirGuest)}, 15*time.Second, 4<<10, guestToolsVerifyOp)
}

// deliverGuestToolsViaShare hot-adds the staged binary as a read-only
// share and copies it into place inside the guest. The share is removed
// afterwards; the copy lives in guest tmpfs for the boot's lifetime.
func (d *daemonRuntime) deliverGuestToolsViaShare(data []byte, sum [32]byte) error {
	if d.shares == nil {
		return fmt.Errorf("share manager unavailable")
	}
	stageDir := filepath.Join(d.dir, guestToolsShareDir)
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		return err
	}
	stagePath := filepath.Join(stageDir, "gantry-guest")
	if err := os.WriteFile(stagePath+".tmp", data, 0o755); err != nil {
		return err
	}
	if err := os.Rename(stagePath+".tmp", stagePath); err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stageDir) }()

	entry, err := d.shares.Add(guestToolsShareTag+"="+stageDir+",ro", false, true)
	if err != nil {
		return fmt.Errorf("share hot-add: %w", err)
	}
	ctrPath := entry.CtrPath
	if ctrPath == "" {
		ctrPath = shares.HubHostPath + "/" + guestToolsShareTag
	}
	defer func() {
		if _, err := d.shares.Remove(guestToolsShareTag, false, true); err != nil {
			fmt.Fprintf(os.Stderr, "daemon: guest tools share cleanup: %v\n", err)
		}
	}()

	script := fmt.Sprintf("mkdir -p %[1]s && cp %[2]s/gantry-guest %[1]s/gantry-guest && chmod 755 %[1]s/gantry-guest && ln -sf gantry-guest %[1]s/credhelper",
		guestToolsDirGuest, ctrPath)
	if _, _, err := d.broker.internalExec(strings.NewReader(""), []string{"sh", "-c", script},
		guestToolsTimeout, 4<<10, guestToolsDeliverOp); err != nil {
		return err
	}
	return d.verifyGuestTools(sum, int64(len(data)))
}

// deliverGuestToolsViaExec streams the base64-encoded binary through the
// session stdin pipe (bulk transfer here risks truncation; the verify step
// makes any loss fail closed).
func (d *daemonRuntime) deliverGuestToolsViaExec(data []byte, sum [32]byte) error {
	var encoded bytes.Buffer
	enc := base64.NewEncoder(base64.StdEncoding, &encoded)
	if _, err := enc.Write(data); err != nil {
		return err
	}
	_ = enc.Close()
	script := fmt.Sprintf("mkdir -p %[1]s && base64 -d > %[1]s/gantry-guest.tmp && chmod 755 %[1]s/gantry-guest.tmp && mv %[1]s/gantry-guest.tmp %[1]s/gantry-guest && ln -sf gantry-guest %[1]s/credhelper", guestToolsDirGuest)
	if _, _, err := d.broker.internalExec(bytes.NewReader(encoded.Bytes()), []string{"sh", "-c", script},
		guestToolsTimeout, 4<<10, guestToolsDeliverOp); err != nil {
		return err
	}
	return d.verifyGuestTools(sum, int64(len(data)))
}

// verifyGuestTools compares the staged guest binary's sha256 and size
// against the host asset. A mismatch is an error; callers fail closed.
func (d *daemonRuntime) verifyGuestTools(sum [32]byte, size int64) error {
	out, _, err := d.broker.internalExec(strings.NewReader(""), []string{"sh", "-c",
		fmt.Sprintf("wc -c < %[1]s/gantry-guest; sha256sum %[1]s/gantry-guest", guestToolsDirGuest)},
		15*time.Second, 4<<10, guestToolsVerifyOp)
	fields := strings.Fields(string(out))
	gotSize, gotSum := "", ""
	if len(fields) > 0 {
		gotSize = fields[0]
	}
	if len(fields) > 1 {
		gotSum = fields[1]
	}
	wantSum := hex.EncodeToString(sum[:])
	if err != nil || gotSum != wantSum || gotSize != fmt.Sprint(size) {
		return fmt.Errorf("integrity check failed (guest %s bytes sha256 %s, want %d bytes sha256 %s; exec err: %v)",
			gotSize, gotSum, size, wantSum, err)
	}
	return nil
}

// readCapped reads path with a hard size ceiling.
func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, max)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(f); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
