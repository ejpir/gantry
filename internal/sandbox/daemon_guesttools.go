package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/secret"

	"github.com/ejpir/gantry/internal/guestasset"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/shares"
)

// Guest-tools delivery: sandboxes configured with host-bound secrets
// (-secret NAME@host) need the multicall helper inside the guest. Two
// channels, in preference order:
//
//  1. share hot-add — the daemon stages the binary outside user share roots,
//     live-adds it at /host/gantry-tools, and invokes its static install-self
//     mode as root to copy it into /run/gantry/bin. The virtio-fs path is
//     built for bulk file data; the exec channel is not.
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
	guestToolsShareDir  = "guesttools" // legacy in-sandbox staging directory; delete cleanup only
	guestToolsDeliverOp = "guest tools delivery"
	guestToolsInstallOp = "guest tools install"
	guestToolsVerifyOp  = "guest tools verify"
	guestToolsTimeout   = 120 * time.Second
)

// hasBoundSecrets reports whether any persisted secret spec carries a
// host binding. Persisted specs may append source refs (=@path, =!argv)
// and ,ttl= suffixes; only the NAME@host head decides.
func hasBoundSecrets(names []string) bool {
	for _, name := range names {
		if _, binding, err := secret.SplitBinding(secret.HeadOf(name)); err == nil && binding != "" {
			return true
		}
	}
	return false
}

// deliverGuestTools stages and installs gantry-guest when the sandbox needs
// it: bound secrets, OAuth custody, MCP, or SSH. MCP blocks readiness because
// its advertised endpoint requires the verified helper; the other consumers
// use asynchronous delivery, and early SSH sessions wait for completion.
// broker.guestToolsReady flips only after content verification.
func (d *daemonRuntime) deliverGuestTools() bool {
	cfg := d.store.Snapshot()
	need := hasBoundSecrets(cfg.SecretNames) || cfg.OAuthCustodyEnabled() || cfg.MCP || cfg.SSH
	if !need {
		return true
	}
	return d.ensureGuestTools(cfg)
}

// deliverGuestToolsAndSignal releases requests waiting for the one boot-time
// delivery attempt whether it succeeds or fails. Success is published before
// the signal by ensureGuestTools, so waiters cannot observe a false negative.
func (d *daemonRuntime) deliverGuestToolsAndSignal() (ready bool) {
	defer d.broker.finishGuestToolsDelivery()
	return d.deliverGuestTools()
}

func (br *broker) finishGuestToolsDelivery() {
	if br == nil {
		return
	}
	br.guestToolsDoneOnce.Do(func() {
		if br.guestToolsDone != nil {
			close(br.guestToolsDone)
		}
	})
}

func (br *broker) waitForGuestTools(ctx context.Context) bool {
	if br == nil {
		return false
	}
	if br.guestToolsReady.Load() {
		return true
	}
	if br.guestToolsDone == nil {
		return false
	}
	select {
	case <-br.guestToolsDone:
		return br.guestToolsReady.Load()
	case <-ctx.Done():
		return false
	}
}

func (d *daemonRuntime) ensureGuestTools(cfg config.RunConfig) bool {
	if d.broker == nil {
		return false
	}
	if d.broker.guestToolsReady.Load() {
		return true
	}
	d.guestToolsMu.Lock()
	defer d.guestToolsMu.Unlock()
	if d.broker.guestToolsReady.Load() {
		return true
	}
	progress := func(format string, a ...any) { fmt.Fprintf(os.Stderr, "daemon: "+format+"\n", a...) }
	// The CLI persists the path it resolved (dev tree, release cache, or
	// GANTRY_ARTIFACTS). Imported and legacy profiles can lack that field;
	// resolve their fallback relative to the executable rather than the
	// daemon's deliberately read-only cwd (/).
	assetPath := cfg.GuestTools
	if assetPath == "" {
		executable, _ := os.Executable()
		assetPath = guestasset.DaemonGuestTools(executable)
	}
	path, err := guestasset.EnsureGuestTools(assetPath, progress)
	if err != nil {
		d.guestToolsFailed("guest tools unavailable: %v", err)
		return false
	}
	data, err := readCapped(path, guestToolsMaxBytes)
	if err != nil {
		d.guestToolsFailed("read guest tools: %v", err)
		return false
	}
	sum := sha256.Sum256(data)

	if err := d.deliverGuestToolsViaShare(data, sum); err == nil {
		d.broker.guestToolsReady.Store(true)
		fmt.Fprintln(os.Stderr, "daemon: guest tools delivered via share")
		return true
	} else {
		fmt.Fprintf(os.Stderr, "daemon: share delivery unavailable (%v); trying exec channel\n", err)
	}
	if err := d.deliverGuestToolsViaExec(data, sum); err == nil {
		d.broker.guestToolsReady.Store(true)
		fmt.Fprintln(os.Stderr, "daemon: guest tools delivered via exec channel")
		return true
	} else {
		d.guestToolsFailed("exec-channel delivery: %v", err)
		return false
	}
}

func (d *daemonRuntime) guestToolsFailed(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "daemon: WARNING: "+format+"\n", a...)
	fmt.Fprintln(os.Stderr, "daemon: guest-tool-backed features will NOT be usable in the guest this boot")
	// Remove whatever landed: a stale or corrupt helper must not be
	// executable (earlier boots may have left one in a persistent layer).
	_, _, _ = d.broker.internalExecAsRoot(strings.NewReader(""), []string{"sh", "-c",
		fmt.Sprintf("rm -rf %[1]s", guestToolsDirGuest)}, 15*time.Second, 4<<10, guestToolsVerifyOp)
}

// deliverGuestToolsViaShare hot-adds the staged binary directly at the
// trusted guest-tools path. Verification executes the static helper itself,
// so distroless images need no shell, cp, wc, or sha256sum.
func (d *daemonRuntime) deliverGuestToolsViaShare(data []byte, sum [32]byte) error {
	if d.shares == nil {
		return fmt.Errorf("share manager unavailable")
	}
	// Sandbox state commonly sits beneath a broad persisted workspace share
	// (for example, the user's whole home directory). Staging there would make
	// this export overlap that share and correctly fail closed. A private OS
	// temporary directory is outside normal workspace roots and is removed only
	// after the share backend closes.
	stageDir, err := os.MkdirTemp("", "gantry-guest-tools-*")
	if err != nil {
		return err
	}
	d.guestToolsStageDir = stageDir
	stagePath := filepath.Join(stageDir, "gantry-guest")
	if err := os.WriteFile(stagePath, data, 0o755); err != nil {
		return err
	}
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

	_, status, err := d.broker.internalExecAsRoot(strings.NewReader(""),
		[]string{ctrPath + "/gantry-guest", "install-self"},
		15*time.Second, 4<<10, guestToolsInstallOp)
	if err != nil {
		return err
	}
	if status != 0 {
		return fmt.Errorf("%s exited with status %d", guestToolsInstallOp, status)
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
	if _, _, err := d.broker.internalExecAsRoot(bytes.NewReader(encoded.Bytes()), []string{"sh", "-c", script},
		guestToolsTimeout, 4<<10, guestToolsDeliverOp); err != nil {
		return err
	}
	return d.verifyGuestTools(sum, int64(len(data)))
}

// verifyGuestTools compares the running guest binary's sha256 and size
// against the host asset. A mismatch is an error; callers fail closed.
func (d *daemonRuntime) verifyGuestTools(sum [32]byte, size int64) error {
	out, _, err := d.broker.internalExecAsRoot(strings.NewReader(""),
		[]string{guestToolsDirGuest + "/gantry-guest", "verify-self"},
		15*time.Second, 4<<10, guestToolsVerifyOp)
	gotSize, gotSum := parseGuestToolsVerification(out)
	wantSum := hex.EncodeToString(sum[:])
	if err != nil || gotSum != wantSum || gotSize != fmt.Sprint(size) {
		return fmt.Errorf("integrity check failed (guest %s bytes sha256 %s, want %d bytes sha256 %s; exec err: %v)",
			gotSize, gotSum, size, wantSum, err)
	}
	return nil
}

// parseGuestToolsVerification finds either the tagged shell-probe result used
// by older helpers or verify-self's two-field output inside an exec transcript.
// Session lifecycle diagnostics may surround the command result.
func parseGuestToolsVerification(out []byte) (size, sum string) {
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "GANTRY_GUEST_TOOLS_VERIFY" {
			fields = fields[1:]
		}
		if len(fields) != 2 || len(fields[1]) != sha256.Size*2 {
			continue
		}
		if decoded, err := hex.DecodeString(fields[1]); err == nil && len(decoded) == sha256.Size {
			size = fields[0]
			sum = strings.ToLower(fields[1])
		}
	}
	return size, sum
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
