//go:build linux || darwin

package sandbox

// Trusted-side process creation and host-socket brokering for _vmm-worker.
// The inherited descriptor table is the worker's complete capability set.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/vmmworker"
	"github.com/ejpir/gantry/internal/workerproto"
)

// spawnVMMWorker re-execs the binary as _vmm-worker with the descriptor
// table and performs the handshake + nonce exchange. cfg counts must
// match the assets (HasRoot ↔ Rootfs and NDisksRO/NDisks) — the worker
// validates too, but failing here keeps the error local.
func spawnVMMWorker(cfg vmmworker.Config, assets vmmworker.Assets, dir string) (*vmmWorker, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("worker re-exec path: %w", err)
	}
	ctrlSup, ctrlWrk, err := socketpairConns()
	if err != nil {
		return nil, err
	}
	bridgeSup, bridgeWrk, err := socketpairConns()
	if err != nil {
		_ = ctrlSup.Close()
		_ = ctrlWrk.Close()
		return nil, err
	}
	fdSup, fdWrk, err := socketpairConns()
	if err != nil {
		_ = ctrlSup.Close()
		_ = ctrlWrk.Close()
		_ = bridgeSup.Close()
		_ = bridgeWrk.Close()
		return nil, err
	}
	shareSup, shareWrk, err := socketpairConns()
	if err != nil {
		_ = ctrlSup.Close()
		_ = ctrlWrk.Close()
		_ = bridgeSup.Close()
		_ = bridgeWrk.Close()
		_ = fdSup.Close()
		_ = fdWrk.Close()
		return nil, err
	}
	keepSup := false
	defer func() {
		if keepSup {
			return
		}
		_ = ctrlSup.Close()
		_ = bridgeSup.Close()
		_ = fdSup.Close()
		_ = shareSup.Close()
	}()
	workerEnds := []net.Conn{ctrlWrk, bridgeWrk, fdWrk, shareWrk}
	// The child duplicates each end into its table slot; the originals
	// close after spawn. dupFiles are supervisor-side duplicates (always
	// closed here). Boot assets stay supervisor-owned until a successful
	// acknowledgement so a failed spawn can degrade to monolithic. Writable
	// disk descriptors remain in the supervisor after acknowledgement: they
	// carry the process-owned exclusive locks for the worker's lifetime.
	var dupFiles []*os.File
	closeDups := func() {
		closeFiles(dupFiles)
		dupFiles = nil
	}
	defer closeDups()
	dupFiles, err = dupConnFiles(workerEnds...)
	if err != nil {
		return nil, fmt.Errorf("worker descriptor table: %w", err)
	}
	if assets.NetConn == nil || assets.Console == nil || assets.Kernel == nil {
		closeDups()
		return nil, fmt.Errorf("descriptor table: net conn, console and kernel are required")
	}
	consoleInfo, err := assets.Console.Stat()
	if err != nil {
		closeDups()
		return nil, fmt.Errorf("descriptor table: inspect console sink: %w", err)
	}
	if consoleInfo.Mode()&os.ModeNamedPipe == 0 {
		closeDups()
		return nil, fmt.Errorf("descriptor table: console must be a supervisor-brokered pipe, got mode %s", consoleInfo.Mode())
	}
	// The net data end is dup'd into the child's slot. Keep the caller's
	// original open until the boot ack: auto mode must be able to reuse it
	// for the monolithic fallback after any spawn/handshake failure.
	netFile, err := connFile(assets.NetConn)
	if err != nil {
		closeDups()
		return nil, err
	}
	dupFiles = append(dupFiles, netFile)
	assetFiles := []*os.File{assets.Console, assets.Kernel}
	closeAfterAck := append([]*os.File(nil), assetFiles...)
	if cfg.HasRoot {
		if assets.Rootfs == nil {
			closeDups()
			return nil, fmt.Errorf("descriptor table: rootfs required")
		}
		assetFiles = append(assetFiles, assets.Rootfs)
		closeAfterAck = append(closeAfterAck, assets.Rootfs)
	}
	if len(assets.DisksRO) != cfg.NDisksRO || len(assets.Disks) != cfg.NDisks {
		closeDups()
		return nil, fmt.Errorf("descriptor table: counts mismatch (disksRO %d/%d, disks %d/%d)",
			len(assets.DisksRO), cfg.NDisksRO, len(assets.Disks), cfg.NDisks)
	}
	assetFiles = append(assetFiles, assets.DisksRO...)
	closeAfterAck = append(closeAfterAck, assets.DisksRO...)
	var maxWritableFileSize uint64
	for index, disk := range assets.Disks {
		if disk == nil {
			return nil, fmt.Errorf("descriptor table: writable disk %d is nil", index)
		}
		if _, err := gutil.TryLockFD(disk); err != nil {
			return nil, fmt.Errorf("lock writable disk %s: %w", disk.Name(), err)
		}
		info, err := disk.Stat()
		if err != nil {
			return nil, fmt.Errorf("stat writable disk %s: %w", disk.Name(), err)
		}
		if info.Size() <= 0 {
			return nil, fmt.Errorf("writable disk %s has invalid size %d", disk.Name(), info.Size())
		}
		if size := uint64(info.Size()); size > maxWritableFileSize {
			maxWritableFileSize = size
		}
	}
	if len(assets.Disks) != 0 {
		cfg.DisksPrelocked = true
		cfg.MaxWritableFileSize = maxWritableFileSize
	}
	assetFiles = append(assetFiles, assets.Disks...)
	if assets.KVM != nil {
		assetFiles = append(assetFiles, assets.KVM) // LAST slot (cfg.HasKVM)
		closeAfterAck = append(closeAfterAck, assets.KVM)
	}
	childFiles := append(append([]*os.File{}, dupFiles...), assetFiles...)

	argv := []string{exe, "_vmm-worker"}
	env := workerEnv()
	if vmmWorkerSpawnHook != nil {
		vmmWorkerSpawnHook(&argv, &env)
	}
	// All three standard descriptors point at a one-way pipe. The trusted
	// supervisor owns and bounds the regular log file; a compromised worker can
	// neither seek/truncate it nor reuse daemon stdout to grow daemon.log. The
	// write-only end at fd 0 also prevents inheritance of the secrets handshake.
	logPath := ""
	if dir != "" {
		logPath = filepath.Join(dir, "worker-vmm.log")
	}
	workerLog, err := newBoundedLogPipe(logPath)
	if err != nil {
		return nil, fmt.Errorf("open VMM worker log broker: %w", err)
	}
	keepWorkerLog := false
	defer func() {
		if !keepWorkerLog {
			_ = workerLog.Close()
		}
	}()
	diagnostic := workerLog.Writer()
	procFiles := append([]*os.File{diagnostic, diagnostic, diagnostic}, childFiles...)
	startProc := func(confine bool) (*os.Process, error) {
		sys := workerSysProcAttr()
		if confine {
			workerConfineProcAttr(sys)
		}
		return os.StartProcess(exe, argv, &os.ProcAttr{
			Env:   env,
			Files: procFiles,
			Sys:   sys,
		})
	}
	confine := cfg.Confinement != "" && cfg.Confinement != "off"
	proc, err := startProc(confine)
	if err != nil && confine && cfg.Confinement == "auto" && isNamespaceUnavailable(err) {
		// Ubuntu 24.04+ AppArmor blocks unprivileged user namespaces for
		// unconfined binaries: degrade to a namespace-less spawn (the
		// worker still self-confines via seccomp; isolation.json reports
		// the honest tier) instead of failing the boot.
		fmt.Fprintf(os.Stderr, "vmm worker: confined spawn denied (%v); retrying without namespaces\n", err)
		proc, err = startProc(false)
	}
	// StartProcess has duplicated the stream into the child (or failed without
	// doing so). Drop the supervisor write end so process death produces EOF.
	workerLog.ReleaseWriter()
	closeDups() // the child has its own table entries now
	if err != nil {
		_ = ctrlSup.Close()
		_ = bridgeSup.Close()
		_ = fdSup.Close()
		return nil, fmt.Errorf("spawn vmm worker: %w", err)
	}

	// waitErr captures the authoritative death cause (signal vs exit
	// code) the first time the child is reaped.
	var waitErr error
	killProc := func() {
		_ = proc.Kill()
		waitErr = waitProcess(proc, "vmm-worker")
	}
	nonce, err := workerproto.NewNonce()
	if err != nil {
		killProc()
		return nil, fmt.Errorf("vmm worker nonce: %w", err)
	}
	if err := workerproto.SendHandshake(ctrlSup, workerproto.RoleVMM, nonce, cfg); err != nil {
		killProc()
		return nil, fmt.Errorf("vmm worker handshake: %w", err)
	}
	if err := workerproto.WriteNonce(fdSup, nonce); err != nil {
		killProc()
		return nil, fmt.Errorf("vmm worker fd nonce: %w", err)
	}
	if err := workerproto.WriteNonce(shareSup, nonce); err != nil {
		killProc()
		return nil, fmt.Errorf("vmm worker share nonce: %w", err)
	}
	// Boot ack: the worker answers after Prepare (machine built) — a
	// missing /dev/kvm or a bad asset surfaces HERE, not as a dead VM
	// minutes later.
	var ack vmmworker.BootAck
	_ = ctrlSup.SetReadDeadline(time.Now().Add(60 * time.Second))
	if err := workerproto.ReadMessage(ctrlSup, &ack); err != nil {
		killProc()
		return nil, fmt.Errorf("vmm worker boot ack: %w (worker wait: %v)", err, waitErr)
	}
	_ = ctrlSup.SetReadDeadline(time.Time{})
	if !ack.OK {
		killProc()
		return nil, fmt.Errorf("vmm worker boot: %s", ack.Error)
	}
	// Handshake complete: the worker owns the boot assets now; close the
	// supervisor's copies (the descriptor table carried them across).
	for _, f := range closeAfterAck {
		_ = f.Close()
	}
	_ = assets.NetConn.Close()

	w := &vmmWorker{
		proc:        proc,
		client:      workerproto.NewClient(ctrlSup),
		fdChan:      fdSup,
		bridge:      bridgeSup,
		bridgeE:     make(chan error, 1),
		share:       shareSup,
		diagnostics: workerLog,
		diskLocks:   assets.Disks,
		lifecycle:   newWorkerLifecycle(),
		confReport:  ack.Confinement,
	}
	go func() {
		w.bridgeE <- workerproto.ServeRequests(bridgeSup, map[string]workerproto.Handler{
			"vsock.forward": w.vsockForward(dir),
		})
	}()
	go func() { w.setDead(waitProcess(proc, "vmm-worker")) }()
	// The drain goroutine now self-owns the broker until worker EOF.
	keepWorkerLog = true
	keepSup = true
	return w, nil
}

// vmmWorkerSpawnHook, when set, rewrites the re-exec argv/env (tests
// only: os.Executable() is the test binary under `go test`).
var vmmWorkerSpawnHook func(argv *[]string, env *[]string)

// vsockForward answers the worker's dial-back bridge: the guest connected
// to a vsock port; the supervisor (owner of all host sockets) dials the
// port's listener in the sandbox dir and transfers the connected
// descriptor. The transfer completes before the OK response, and the
// worker pre-registers its receive — neither side can deadlock.
func (w *vmmWorker) vsockForward(dir string) workerproto.Handler {
	return func(req workerproto.Request) (any, error) {
		var body vmmworker.ForwardRequest
		if err := workerproto.DecodeBody(req, &body); err != nil {
			return nil, fmt.Errorf("vsock.forward: %w", err)
		}
		token, err := hex.DecodeString(body.Token)
		if err != nil || len(token) != workerproto.FDTokenLen {
			return nil, fmt.Errorf("vsock.forward: bad token")
		}
		var tok [workerproto.FDTokenLen]byte
		copy(tok[:], token)
		sock := filepath.Join(dir, fmt.Sprintf("%d.sock", body.Port))
		conn, err := net.DialTimeout("unix", sock, 3*time.Second)
		if err != nil {
			return nil, fmt.Errorf("vsock.forward %s: %w", sock, err)
		}
		f, err := connFile(conn)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		err = w.sendFD(tok, f)
		_ = f.Close()
		_ = conn.Close()
		if err != nil {
			return nil, fmt.Errorf("vsock.forward: %w", err)
		}
		return nil, nil
	}
}

// isNamespaceUnavailable reports failures that mean the requested namespace
// tier cannot be created on this host. Besides policy denials, Linux can
// return ENOSPC or EUSERS when user/PID namespace quotas are exhausted. Auto
// mode may honestly degrade around those host constraints; required mode
// still fails closed. EINVAL is intentionally excluded because it can also
// identify malformed spawn attributes rather than an unavailable facility.
func isNamespaceUnavailable(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EUSERS)
}
