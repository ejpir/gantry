//go:build linux || darwin

package vmmworker

// Trusted-side process creation and host-socket brokering for _vmm-worker.
// The inherited descriptor table is the worker's complete capability set.

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox/boundedlog"
	"github.com/ejpir/gantry/internal/sandbox/worker"
	vmmworkerapi "github.com/ejpir/gantry/internal/vmmworker"
	"github.com/ejpir/gantry/internal/workerproto"
)

// spawnVMMWorker re-execs the binary as _vmm-worker with the descriptor
// table and performs the handshake + nonce exchange. cfg counts must
// match the assets (HasRoot ↔ Rootfs and NDisksRO/NDisks) — the worker
// validates too, but failing here keeps the error local.
func spawnVMMWorker(cfg vmmworkerapi.Config, assets vmmworkerapi.Assets, dir string) (*vmmWorker, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("worker re-exec path: %w", err)
	}
	ctrlSup, ctrlWrk, err := worker.SocketpairConns()
	if err != nil {
		return nil, err
	}
	bridgeSup, bridgeWrk, err := worker.SocketpairConns()
	if err != nil {
		_ = ctrlSup.Close()
		_ = ctrlWrk.Close()
		return nil, err
	}
	fdSup, fdWrk, err := worker.SocketpairConns()
	if err != nil {
		_ = ctrlSup.Close()
		_ = ctrlWrk.Close()
		_ = bridgeSup.Close()
		_ = bridgeWrk.Close()
		return nil, err
	}
	shareSup, shareWrk, err := worker.SocketpairConns()
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
	// acknowledgement so a failed spawn can degrade to monolithic — the
	// writable-disk locks included, since the monolithic fallback has to be
	// able to take them itself.
	var dupFiles []*os.File
	closeDups := func() {
		worker.CloseFiles(dupFiles)
		dupFiles = nil
	}
	defer closeDups()
	dupFiles, err = worker.DupConnFiles(workerEnds...)
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
	netFile, err := worker.ConnFile(assets.NetConn)
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
	// Each writable disk is locked on a private description the child never
	// receives: flock ownership follows the open file description, so the
	// worker's inherited descriptor cannot unlock what the supervisor holds.
	var diskLocks []*os.File
	keepDiskLocks := false
	defer func() {
		if !keepDiskLocks {
			worker.CloseFiles(diskLocks)
		}
	}()
	var maxWritableFileSize uint64
	for index, disk := range assets.Disks {
		if disk == nil {
			return nil, fmt.Errorf("descriptor table: writable disk %d is nil", index)
		}
		lock, err := gutil.TryLockPrivate(disk)
		if err != nil {
			return nil, fmt.Errorf("lock writable disk %s: %w", disk.Name(), err)
		}
		diskLocks = append(diskLocks, lock)
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
	closeAfterAck = append(closeAfterAck, assets.Disks...)
	var vhostPipes []*os.File
	defer worker.CloseFiles(vhostPipes)
	if cfg.VhostShares {
		if !cfg.HasSharedRAM || assets.SharedRAM == nil {
			return nil, fmt.Errorf("descriptor table: vhost shares require shared RAM")
		}
		assetFiles = append(assetFiles, assets.SharedRAM)
		closeAfterAck = append(closeAfterAck, assets.SharedRAM)
		for queue := 0; queue < vmmworkerapi.VhostQueueCount; queue++ {
			kickRead, kickWrite, err := os.Pipe()
			if err != nil {
				return nil, fmt.Errorf("vhost queue %d kick pipe: %w", queue, err)
			}
			vhostPipes = append(vhostPipes, kickRead, kickWrite)
			callRead, callWrite, err := os.Pipe()
			if err != nil {
				return nil, fmt.Errorf("vhost queue %d call pipe: %w", queue, err)
			}
			vhostPipes = append(vhostPipes, callRead, callWrite)
			assetFiles = append(assetFiles, kickRead, kickWrite, callRead, callWrite)
		}
	} else if cfg.HasSharedRAM || assets.SharedRAM != nil {
		return nil, fmt.Errorf("descriptor table: shared RAM without vhost shares")
	}
	if assets.KVM != nil {
		assetFiles = append(assetFiles, assets.KVM) // LAST slot (cfg.HasKVM)
		closeAfterAck = append(closeAfterAck, assets.KVM)
	}
	childFiles := append(append([]*os.File{}, dupFiles...), assetFiles...)

	argv := []string{exe, "_vmm-worker"}
	env := worker.Env()
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
	workerLog, err := boundedlog.NewPipe(logPath)
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
		sys := worker.SysProcAttr()
		if confine {
			worker.ConfineProcAttr(sys)
		}
		return os.StartProcess(exe, argv, &os.ProcAttr{
			Env:   env,
			Files: procFiles,
			Sys:   sys,
		})
	}
	confine := cfg.Confinement != "" && cfg.Confinement != "off"
	proc, err := startProc(confine)
	if err != nil && confine && cfg.Confinement == "auto" && worker.IsNamespaceUnavailable(err) {
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
		waitErr = worker.WaitProcess(proc, "vmm-worker")
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
	var ack vmmworkerapi.BootAck
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
		proc:           proc,
		client:         workerproto.NewClient(ctrlSup),
		fdChan:         fdSup,
		bridge:         bridgeSup,
		bridgeE:        make(chan error, 1),
		share:          shareSup,
		diagnostics:    workerLog,
		diagnosticPath: logPath,
		diskLocks:      diskLocks,
		lifecycle:      worker.NewLifecycle(),
		confReport:     ack.Confinement,
	}
	go func() {
		w.bridgeE <- workerproto.ServeRequests(bridgeSup, map[string]workerproto.Handler{
			"vsock.forward": w.vsockForward(dir),
		})
	}()
	go func() { w.setDead(worker.WaitProcess(proc, "vmm-worker")) }()
	// The drain goroutine now self-owns the broker until worker EOF.
	keepWorkerLog = true
	keepSup = true
	keepDiskLocks = true // released by revokeWorkerCapabilities
	return w, nil
}

// vsockForward answers the worker's dial-back bridge: the guest connected
// to a vsock port; the supervisor (owner of all host sockets) dials the
// port's listener in the sandbox dir and transfers the connected
// descriptor. The transfer completes before the OK response, and the
// worker pre-registers its receive — neither side can deadlock.
func (w *vmmWorker) vsockForward(dir string) workerproto.Handler {
	return func(req workerproto.Request) (any, error) {
		var body vmmworkerapi.ForwardRequest
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
		f, err := worker.ConnFile(conn)
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
