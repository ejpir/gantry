package vmmworker

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/worker"
	vmmworkerapi "github.com/ejpir/gantry/internal/vmmworker"
	"github.com/ejpir/gantry/internal/workerproto"
)

func spawnVMMWorker(cfg vmmworkerapi.Config, assets vmmworkerapi.Assets, dir string) (*vmmWorker, error) {
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
	netFile, err := worker.ConnFile(assets.NetConn)
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

	// Logical slot 7 is reserved for the connected network socket transferred
	// after CreateProcess. Static boot handles begin at slot 8, matching the
	// child-side WHPX descriptor contract.
	inherited := make([]worker.InheritedFile, 0, len(assetFiles))
	for index, file := range assetFiles {
		inherited = append(inherited, worker.InheritedFile{Slot: 8 + index, File: file})
	}
	logPath := ""
	if dir != "" {
		logPath = filepath.Join(dir, "worker-vmm.log")
	}
	child, err := worker.Launch(worker.LaunchSpec{
		Role:             workerproto.RoleVMM,
		EntryPoint:       "_vmm-worker",
		Environment:      vmmWorkerEnv(),
		Channels:         []string{"control", "bridge", "fd", "share"},
		InheritedFiles:   inherited,
		DiagnosticPath:   logPath,
		Confinement:      cfg.Confinement,
		ConfigureProcess: vmmWorkerSpawnHook,
	})
	if err != nil {
		return nil, err
	}
	ctrlSup := child.Channels["control"]
	bridgeSup := child.Channels["bridge"]
	fdSup := workerproto.ForProcess(child.Channels["fd"], uint32(child.Process.Pid))
	shareSup := child.Channels["share"]

	var waitErr error
	killChild := func() {
		_ = child.Terminate(5 * time.Second)
		waitErr = child.Err()
	}
	bootstrap, err := child.BeginBootstrap(cfg)
	if err != nil {
		killChild()
		return nil, fmt.Errorf("vmm worker handshake: %w", err)
	}
	var netToken [workerproto.FDTokenLen]byte
	if err := workerproto.SendFD(fdSup, netToken, netFile); err != nil {
		killChild()
		return nil, fmt.Errorf("vmm worker net socket: %w", err)
	}
	if err := bootstrap.BindChannels("fd", "share"); err != nil {
		killChild()
		return nil, fmt.Errorf("vmm worker channel nonce: %w", err)
	}

	var ack vmmworkerapi.BootAck
	_ = ctrlSup.SetReadDeadline(time.Now().Add(60 * time.Second))
	if err := workerproto.ReadMessage(ctrlSup, &ack); err != nil {
		killChild()
		return nil, fmt.Errorf("vmm worker boot ack: %w (worker wait: %v)", err, waitErr)
	}
	_ = ctrlSup.SetReadDeadline(time.Time{})
	if !ack.OK {
		killChild()
		return nil, fmt.Errorf("vmm worker boot: %s", ack.Error)
	}
	for _, file := range closeAfterAck {
		_ = file.Close()
	}
	_ = assets.NetConn.Close()

	w := &vmmWorker{
		child: child, proc: child.Process, client: workerproto.NewClient(ctrlSup), fdChan: fdSup,
		bridge: bridgeSup, bridgeE: make(chan error, 1), share: shareSup,
		lifecycle: child.Lifecycle, confReport: ack.Confinement,
	}
	go func() {
		w.bridgeE <- workerproto.ServeRequests(bridgeSup, map[string]workerproto.Handler{
			"vsock.forward": w.vsockForward(dir),
		})
	}()
	go w.observeChild()
	return w, nil
}

func (w *vmmWorker) vsockForward(dir string) workerproto.Handler {
	return func(req workerproto.Request) (any, error) {
		var body vmmworkerapi.ForwardRequest
		if err := workerproto.DecodeBody(req, &body); err != nil {
			return nil, fmt.Errorf("vsock.forward: %w", err)
		}
		decoded, err := hex.DecodeString(body.Token)
		if err != nil || len(decoded) != workerproto.FDTokenLen {
			return nil, fmt.Errorf("vsock.forward: bad token")
		}
		var token [workerproto.FDTokenLen]byte
		copy(token[:], decoded)
		socket := filepath.Join(dir, fmt.Sprintf("%d.sock", body.Port))
		conn, err := net.DialTimeout("unix", socket, 3*time.Second)
		if err != nil {
			return nil, fmt.Errorf("vsock.forward %s: %w", socket, err)
		}
		file, err := worker.ConnFile(conn)
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
