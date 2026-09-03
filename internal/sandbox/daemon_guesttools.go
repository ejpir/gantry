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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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
//  1. share hot-add — the daemon stages the binary in a private host directory,
//     live-adds it at /host/gantry-tools, and invokes its static install-self
//     mode as root to copy it into /run/gantry/bin. The virtio-fs path is
//     built for bulk file data; the exec channel is not.
//  2. exec-channel fallback (no virtio-fs hub, or -rw=false) — base64
//     through the session stdin pipe. Small commands only: bulk transfer
//     over this channel risks truncation under load.
//
// Both paths end with a guest-side sha256+size verification before the
// selected workload or IDE readiness bit flips: a mangled helper must never
// become executable guest authority. Workload delivery failure is fatal when
// MCP, bound credentials, or OAuth custody require it; asynchronous SSH
// delivery failure leaves the VM ready but refuses SSH for that boot.
const (
	guestToolsMaxBytes     = 64 << 20
	guestToolsDirGuest     = "/run/gantry/bin"
	guestToolsShareTag     = "gantry-tools"
	guestToolsShareDir     = "guesttools" // legacy in-sandbox staging directory; delete cleanup only
	guestToolsDeliverOp    = "guest tools delivery"
	guestToolsInstallOp    = "guest tools install"
	guestToolsVerifyOp     = "guest tools verify"
	guestToolsShareTimeout = 30 * time.Second
	guestToolsTimeout      = 120 * time.Second
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

func (br *broker) guestToolsState(ide bool) (*atomic.Bool, chan struct{}, *sync.Once) {
	if ide {
		return &br.ideToolsReady, br.ideToolsDone, &br.ideToolsDoneOnce
	}
	return &br.guestToolsReady, br.guestToolsDone, &br.guestToolsDoneOnce
}

func (br *broker) finishGuestToolsDelivery(ide bool) {
	if br == nil {
		return
	}
	_, done, once := br.guestToolsState(ide)
	once.Do(func() {
		if done != nil {
			close(done)
		}
	})
}

func (br *broker) waitForGuestTools(ctx context.Context, ide bool) bool {
	if br == nil {
		return false
	}
	ready, done, _ := br.guestToolsState(ide)
	if ready.Load() {
		return true
	}
	if done == nil {
		return false
	}
	select {
	case <-done:
		return ready.Load()
	case <-ctx.Done():
		return false
	}
}

type guestToolsTarget struct {
	ide   bool
	label string
}

type guestToolsBootPlan struct {
	workloadRequired bool
	workloadAsync    bool
	ideAsync         bool
}

func planGuestToolsDelivery(cfg config.RunConfig) guestToolsBootPlan {
	required := cfg.MCP || hasBoundSecrets(cfg.SecretNames) || cfg.OAuthCustodyEnabled()
	return guestToolsBootPlan{
		workloadRequired: required,
		workloadAsync:    !required && cfg.SSH && !cfg.DevContainers,
		ideAsync:         cfg.SSH && cfg.DevContainers,
	}
}

func guestToolsTargets(cfg config.RunConfig) []guestToolsTarget {
	plan := planGuestToolsDelivery(cfg)
	var targets []guestToolsTarget
	if plan.workloadRequired || plan.workloadAsync {
		targets = append(targets, guestToolsTarget{label: "workload"})
	}
	if plan.ideAsync {
		targets = append(targets, guestToolsTarget{ide: true, label: "IDE"})
	}
	return targets
}

// beginGuestToolsDelivery joins one delivery to the daemon lifetime. Add and
// stop are serialized so a Wait can never race a zero-to-one WaitGroup edge.
func (d *daemonRuntime) beginGuestToolsDelivery() (context.Context, func(), bool) {
	d.guestToolsLifeMu.Lock()
	defer d.guestToolsLifeMu.Unlock()
	if d.guestToolsStopping {
		return nil, nil, false
	}
	if d.guestToolsCtx == nil {
		d.guestToolsCtx, d.guestToolsCancel = context.WithCancel(context.Background())
	}
	d.guestToolsWG.Add(1)
	return d.guestToolsCtx, d.guestToolsWG.Done, true
}

// stopGuestToolsDelivery prevents new deliveries, cancels current internal
// execs, and joins all synchronous or asynchronous owners. It is safe to call
// from gracefulStop and again from deferred close.
func (d *daemonRuntime) stopGuestToolsDelivery() {
	d.guestToolsLifeMu.Lock()
	d.guestToolsStopping = true
	cancel := d.guestToolsCancel
	d.guestToolsLifeMu.Unlock()
	if cancel != nil {
		cancel()
	}
	d.guestToolsWG.Wait()
}

func (d *daemonRuntime) finishGuestToolsTargets(targets []guestToolsTarget) {
	for _, target := range targets {
		d.broker.finishGuestToolsDelivery(target.ide)
	}
}

func (d *daemonRuntime) ensureGuestToolsTargetsAndSignal(cfg config.RunConfig, targets []guestToolsTarget) bool {
	ctx, done, ok := d.beginGuestToolsDelivery()
	if !ok {
		d.finishGuestToolsTargets(targets)
		return false
	}
	defer done()
	return d.ensureGuestToolsTargetsAndSignalContext(ctx, cfg, targets)
}

func (d *daemonRuntime) startAsyncGuestToolsDelivery(cfg config.RunConfig, targets []guestToolsTarget) {
	ctx, done, ok := d.beginGuestToolsDelivery()
	if !ok {
		d.finishGuestToolsTargets(targets)
		return
	}
	go func() {
		defer done()
		d.ensureGuestToolsTargetsAndSignalContext(ctx, cfg, targets)
	}()
}

func (d *daemonRuntime) ensureGuestToolsTargetsAndSignalContext(ctx context.Context, cfg config.RunConfig, targets []guestToolsTarget) bool {
	defer d.finishGuestToolsTargets(targets)
	return d.ensureGuestToolsTargets(ctx, cfg, targets)
}

func (d *daemonRuntime) ensureGuestToolsTargets(ctx context.Context, cfg config.RunConfig, targets []guestToolsTarget) bool {
	if d.broker == nil || ctx.Err() != nil {
		return false
	}
	d.guestToolsMu.Lock()
	defer d.guestToolsMu.Unlock()
	if ctx.Err() != nil {
		return false
	}
	pending := make([]guestToolsTarget, 0, len(targets))
	for _, target := range targets {
		ready, _, _ := d.broker.guestToolsState(target.ide)
		if !ready.Load() {
			pending = append(pending, target)
		}
	}
	targets = pending
	if len(targets) == 0 {
		return true
	}
	progress := func(format string, a ...any) { fmt.Fprintf(os.Stderr, "daemon: "+format+"\n", a...) }
	assetPath := cfg.GuestTools
	if assetPath == "" {
		executable, _ := os.Executable()
		assetPath = guestasset.DaemonGuestTools(executable)
	}
	path, err := guestasset.EnsureGuestTools(assetPath, progress)
	if err != nil {
		if ctx.Err() == nil {
			d.guestToolsFailed(ctx, targets, "guest tools unavailable: %v", err)
		}
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	data, err := readCapped(path, guestToolsMaxBytes)
	if err != nil {
		if ctx.Err() == nil {
			d.guestToolsFailed(ctx, targets, "read guest tools: %v", err)
		}
		return false
	}
	sum := sha256.Sum256(data)

	if err := d.deliverGuestToolsViaShare(ctx, data, sum, targets); err == nil {
		for _, target := range targets {
			ready, _, _ := d.broker.guestToolsState(target.ide)
			ready.Store(true)
		}
		fmt.Fprintln(os.Stderr, "daemon: guest tools delivered via share")
		return true
	} else {
		if ctx.Err() != nil {
			return false
		}
		fmt.Fprintf(os.Stderr, "daemon: share delivery unavailable (%v); trying exec channel\n", err)
	}
	if err := d.deliverGuestToolsViaExec(ctx, data, sum, targets); err == nil {
		for _, target := range targets {
			ready, _, _ := d.broker.guestToolsState(target.ide)
			ready.Store(true)
		}
		fmt.Fprintln(os.Stderr, "daemon: guest tools delivered via exec channel")
		return true
	} else {
		if ctx.Err() == nil {
			d.guestToolsFailed(ctx, targets, "exec-channel delivery: %v", err)
		}
		return false
	}
}

func (d *daemonRuntime) guestToolsFailed(ctx context.Context, targets []guestToolsTarget, format string, a ...any) {
	fmt.Fprintf(os.Stderr, "daemon: WARNING: "+format+"\n", a...)
	fmt.Fprintln(os.Stderr, "daemon: guest-tool-backed features will NOT be usable in the guest this boot")
	for _, target := range targets {
		_, _, _ = d.broker.internalExecAsRootTargetContext(ctx, strings.NewReader(""), []string{"sh", "-c",
			fmt.Sprintf("rm -rf %[1]s", guestToolsDirGuest)}, 15*time.Second, 4<<10, guestToolsVerifyOp, target.ide)
	}
}

// withGuestToolsStage owns one attempt's temporary payload. Cleanup is local
// rather than deferred to daemon shutdown, so retries cannot overwrite or
// accumulate staging-directory state.
func withGuestToolsStage(base string, data []byte, use func(string) error) error {
	stageDir, err := os.MkdirTemp(base, "gantry-guest-tools-*")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(stageDir); err != nil {
			fmt.Fprintf(os.Stderr, "daemon: guest tools staging cleanup: %v\n", err)
		}
	}()
	if err := os.WriteFile(filepath.Join(stageDir, "gantry-guest"), data, 0o755); err != nil {
		return err
	}
	return use(stageDir)
}

// deliverGuestToolsViaShare exposes one verified host payload and installs it
// independently into every OCI root that advertises helper-backed features.
func (d *daemonRuntime) deliverGuestToolsViaShare(ctx context.Context, data []byte, sum [32]byte, targets []guestToolsTarget) error {
	if d.shares == nil {
		return fmt.Errorf("share manager unavailable")
	}
	stageBase := guestToolsStageBase(runtime.GOOS, d.dir)
	if runtime.GOOS == "windows" && stageBase == "" {
		return fmt.Errorf("sandbox state directory unavailable for guest-tools staging")
	}
	return withGuestToolsStage(stageBase, data, func(stageDir string) error {
		if err := ctx.Err(); err != nil {
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
		for _, target := range targets {
			if err := d.installGuestToolsFromShare(ctx, ctrPath, sum, int64(len(data)), target); err != nil {
				return fmt.Errorf("%s helper install: %w", target.label, err)
			}
		}
		return nil
	})
}

func (d *daemonRuntime) installGuestToolsFromShare(ctx context.Context, ctrPath string, sum [32]byte, size int64, target guestToolsTarget) error {
	status := -1
	directErr := fmt.Errorf("host share does not expose executable mode")
	if runtime.GOOS != "windows" {
		_, status, directErr = d.broker.internalExecAsRootTargetContext(ctx, strings.NewReader(""),
			[]string{ctrPath + "/gantry-guest", "install-self"},
			15*time.Second, 4<<10, guestToolsInstallOp, target.ide)
		if directErr == nil && status == 0 {
			return d.verifyGuestTools(ctx, sum, size, target)
		}
	}
	copyScript := fmt.Sprintf("mkdir -p %[1]s && rm -f %[1]s/gantry-guest.share %[1]s/gantry-guest %[1]s/credhelper && cp \"$1\" %[1]s/gantry-guest.share && chmod 755 %[1]s/gantry-guest.share && mv %[1]s/gantry-guest.share %[1]s/gantry-guest && ln %[1]s/gantry-guest %[1]s/credhelper", guestToolsDirGuest)
	copyOut, copyStatus, copyErr := d.broker.internalExecAsRootTargetContext(ctx, strings.NewReader(""),
		[]string{"sh", "-c", copyScript, "gantry-guest-share-copy", ctrPath + "/gantry-guest"},
		guestToolsShareTimeout, 4<<10, guestToolsInstallOp, target.ide)
	if copyErr != nil {
		return fmt.Errorf("execute shared helper: %v; copy shared helper: %w (output %q)", directErr, copyErr, copyOut)
	}
	if copyStatus != 0 {
		return fmt.Errorf("execute shared helper status %d; copy shared helper exited with status %d (output %q)", status, copyStatus, copyOut)
	}
	return d.verifyGuestTools(ctx, sum, size, target)
}

func (d *daemonRuntime) deliverGuestToolsViaExec(ctx context.Context, data []byte, sum [32]byte, targets []guestToolsTarget) error {
	var encoded bytes.Buffer
	enc := base64.NewEncoder(base64.StdEncoding, &encoded)
	if _, err := enc.Write(data); err != nil {
		return err
	}
	_ = enc.Close()
	script := fmt.Sprintf("mkdir -p %[1]s && base64 -d > %[1]s/gantry-guest.tmp && chmod 755 %[1]s/gantry-guest.tmp && mv %[1]s/gantry-guest.tmp %[1]s/gantry-guest && ln -sf gantry-guest %[1]s/credhelper", guestToolsDirGuest)
	for _, target := range targets {
		if _, _, err := d.broker.internalExecAsRootTargetContext(ctx, bytes.NewReader(encoded.Bytes()), []string{"sh", "-c", script},
			guestToolsTimeout, 4<<10, guestToolsDeliverOp, target.ide); err != nil {
			return fmt.Errorf("%s helper stream: %w", target.label, err)
		}
		if err := d.verifyGuestTools(ctx, sum, int64(len(data)), target); err != nil {
			return err
		}
	}
	return nil
}

func (d *daemonRuntime) verifyGuestTools(ctx context.Context, sum [32]byte, size int64, target guestToolsTarget) error {
	out, _, err := d.broker.internalExecAsRootTargetContext(ctx, strings.NewReader(""),
		[]string{guestToolsDirGuest + "/gantry-guest", "verify-self"},
		15*time.Second, 4<<10, guestToolsVerifyOp, target.ide)
	gotSize, gotSum := parseGuestToolsVerification(out)
	wantSum := hex.EncodeToString(sum[:])
	if err != nil || gotSum != wantSum || gotSize != fmt.Sprint(size) {
		return fmt.Errorf("%s integrity check failed (guest %s bytes sha256 %s, want %d bytes sha256 %s; exec err: %v)",
			target.label, gotSize, gotSum, size, wantSum, err)
	}
	return nil
}

// guestToolsStageBase keeps Windows staging in Gantry-owned sandbox state.
// An empty base deliberately selects the OS temporary directory on Unix.
func guestToolsStageBase(goos, sandboxDir string) string {
	if goos == "windows" {
		return sandboxDir
	}
	return ""
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
