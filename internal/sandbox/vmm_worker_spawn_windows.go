package sandbox

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ejpir/gantry/internal/vmmworker"
	"github.com/ejpir/gantry/internal/workerproto"
)

func spawnVMMWorker(cfg vmmworker.Config, assets vmmworker.Assets, dir string) (*vmmWorker, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("worker re-exec path: %w", err)
	}
	channels, channelFiles, err := workerPipeChannels(4)
	if err != nil {
		return nil, err
	}
	defer closeFiles(channelFiles)
	ctrlSup, bridgeSup, fdSup, shareSup := channels[0], channels[1], channels[2], channels[3]
	keepSupervisor := false
	defer func() {
		if keepSupervisor {
			return
		}
		for _, conn := range []net.Conn{ctrlSup, bridgeSup, fdSup, shareSup} {
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	if assets.NetConn == nil || assets.Console == nil || assets.Kernel == nil {
		return nil, fmt.Errorf("handle table: net conn, console and kernel are required")
	}
	consoleInfo, err := assets.Console.Stat()
	if err != nil {
		return nil, fmt.Errorf("handle table: inspect console sink: %w", err)
	}
	if consoleInfo.Mode()&os.ModeNamedPipe == 0 {
		return nil, fmt.Errorf("handle table: console must be a supervisor-brokered pipe, got mode %s", consoleInfo.Mode())
	}
	netFile, err := connFile(assets.NetConn)
	if err != nil {
		return nil, fmt.Errorf("handle table: net conn: %w", err)
	}
	defer func() { _ = netFile.Close() }()

	assetFiles := []*os.File{assets.Console, assets.Kernel}
	closeAfterAck := append([]*os.File(nil), assetFiles...)
	if cfg.HasRoot {
		if assets.Rootfs == nil {
			return nil, fmt.Errorf("handle table: rootfs required")
		}
		assetFiles = append(assetFiles, assets.Rootfs)
		closeAfterAck = append(closeAfterAck, assets.Rootfs)
	}
	if len(assets.DisksRO) != cfg.NDisksRO || len(assets.Disks) != cfg.NDisks {
		return nil, fmt.Errorf("handle table: counts mismatch (disksRO %d/%d, disks %d/%d)",
			len(assets.DisksRO), cfg.NDisksRO, len(assets.Disks), cfg.NDisks)
	}
	assetFiles = append(assetFiles, assets.DisksRO...)
	closeAfterAck = append(closeAfterAck, assets.DisksRO...)

	for index, disk := range assets.Disks {
		if disk == nil {
			return nil, fmt.Errorf("handle table: writable disk %d is nil", index)
		}
		info, err := disk.Stat()
		if err != nil {
			return nil, fmt.Errorf("stat writable disk %s: %w", disk.Name(), err)
		}
		if info.Size() <= 0 {
			return nil, fmt.Errorf("writable disk %s has invalid size %d", disk.Name(), info.Size())
		}
	}
	assetFiles = append(assetFiles, assets.Disks...)
	closeAfterAck = append(closeAfterAck, assets.Disks...)
	if cfg.VhostShares || cfg.HasSharedRAM || assets.SharedRAM != nil || assets.KVM != nil {
		return nil, fmt.Errorf("handle table: Unix vhost/KVM assets are unavailable with WHPX")
	}

	sources := append(append([]*os.File{}, channelFiles...), assetFiles...)
	childHandles, err := inheritableHandles(sources)
	if err != nil {
		return nil, err
	}
	defer clearInheritedHandles(childHandles)

	argv := []string{exe, "_vmm-worker"}
	env := workerEnv()
	if vmmWorkerSpawnHook != nil {
		vmmWorkerSpawnHook(&argv, &env)
	}
	env = workerPipeEnv(env, channelFiles, 3)
	env = workerHandleEnv(env, assetFiles, 8)
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
	proc, containment, err := startWindowsWorkerProcess(exe, argv, env,
		[]*os.File{diagnostic, diagnostic, diagnostic}, childHandles, cfg.Confinement)
	workerLog.ReleaseWriter()
	// CreateProcess has duplicated the child ends. Drop the supervisor copies
	// now so worker death produces EOF on every channel instead of leaving the
	// handshake parked until its deadline.
	closeFiles(channelFiles)
	channelFiles = nil
	if err != nil {
		return nil, fmt.Errorf("spawn vmm worker: %w", err)
	}
	fdSup = workerproto.ForProcess(fdSup, uint32(proc.Pid))

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
	var netToken [workerproto.FDTokenLen]byte
	if err := workerproto.SendFD(fdSup, netToken, netFile); err != nil {
		killProc()
		return nil, fmt.Errorf("vmm worker net socket: %w", err)
	}
	if err := workerproto.WriteNonce(fdSup, nonce); err != nil {
		killProc()
		return nil, fmt.Errorf("vmm worker socket nonce: %w", err)
	}
	if err := workerproto.WriteNonce(shareSup, nonce); err != nil {
		killProc()
		return nil, fmt.Errorf("vmm worker share nonce: %w", err)
	}
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
	for _, file := range closeAfterAck {
		_ = file.Close()
	}
	_ = assets.NetConn.Close()

	w := &vmmWorker{
		proc: proc, client: workerproto.NewClient(ctrlSup), fdChan: fdSup,
		bridge: bridgeSup, bridgeE: make(chan error, 1), share: shareSup,
		diagnostics: workerLog, containment: containment, lifecycle: newWorkerLifecycle(),
		confReport: ack.Confinement,
	}
	go func() {
		w.bridgeE <- workerproto.ServeRequests(bridgeSup, map[string]workerproto.Handler{
			"vsock.forward": w.vsockForward(dir),
		})
	}()
	go func() { w.setDead(waitProcess(proc, "vmm-worker")) }()
	keepWorkerLog = true
	keepSupervisor = true
	return w, nil
}

func (w *vmmWorker) vsockForward(dir string) workerproto.Handler {
	return func(req workerproto.Request) (any, error) {
		var body vmmworker.ForwardRequest
		if err := workerproto.DecodeBody(req, &body); err != nil {
			return nil, fmt.Errorf("vsock.forward: %w", err)
		}
		decoded, err := hex.DecodeString(body.Token)
		if err != nil || len(decoded) != workerproto.FDTokenLen {
			return nil, fmt.Errorf("vsock.forward: bad token")
		}
		var token [workerproto.FDTokenLen]byte
		copy(token[:], decoded)
		sock := filepath.Join(dir, fmt.Sprintf("%d.sock", body.Port))
		conn, err := net.DialTimeout("unix", sock, 3*time.Second)
		if err != nil {
			return nil, fmt.Errorf("vsock.forward %s: %w", sock, err)
		}
		file, err := connFile(conn)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		err = w.sendFD(token, file)
		_ = file.Close()
		_ = conn.Close()
		if err != nil {
			return nil, fmt.Errorf("vsock.forward: %w", err)
		}
		return nil, nil
	}
}
