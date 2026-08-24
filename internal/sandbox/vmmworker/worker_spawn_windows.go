package vmmworker

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/worker"
	"github.com/ejpir/gantry/internal/vmm"
	vmmworkerapi "github.com/ejpir/gantry/internal/vmmworker"
	"github.com/ejpir/gantry/internal/workerproto"
)

func spawnVMMWorker(cfg vmmworkerapi.Config, assets vmmworkerapi.Assets, dir string) (*vmmWorker, error) {
	if assets.Console == nil || assets.Kernel == nil {
		return nil, fmt.Errorf("handle table: console and kernel are required")
	}
	if cfg.NoNetwork != (assets.NetConn == nil) {
		return nil, fmt.Errorf("handle table: network presence does not match boot config")
	}
	consoleInfo, err := assets.Console.Stat()
	if err != nil {
		return nil, fmt.Errorf("handle table: inspect console sink: %w", err)
	}
	if consoleInfo.Mode()&os.ModeNamedPipe == 0 {
		return nil, fmt.Errorf("handle table: console must be a supervisor-brokered pipe, got mode %s", consoleInfo.Mode())
	}
	var netFile *os.File
	if assets.NetConn != nil {
		netFile, err = worker.ConnFile(assets.NetConn)
		if err != nil {
			return nil, fmt.Errorf("handle table: net conn: %w", err)
		}
		defer func() { _ = netFile.Close() }()
	}

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
	if cfg.VhostShares || assets.KVM != nil {
		return nil, fmt.Errorf("handle table: Unix vhost/KVM assets are unavailable with WHPX")
	}
	if cfg.WHPXBroker != cfg.HasSharedRAM || cfg.WHPXBroker != (assets.SharedRAM != nil) {
		return nil, fmt.Errorf("handle table: brokered WHPX requires exactly one shared RAM section")
	}

	var (
		brokerChild *worker.Child
		targetPeer  [2]*os.File
		mailboxes   vmm.WHPXMailboxFiles
	)
	if cfg.WHPXBroker {
		mailboxes, err = vmm.NewWHPXMailboxFiles(cfg.VCPUs)
		if err != nil {
			return nil, err
		}
		defer func() { _ = mailboxes.Close() }()
		var frequency uint64
		brokerChild, targetPeer, frequency, err = spawnWHPXBroker(cfg, assets.SharedRAM, mailboxes, dir)
		if err != nil {
			return nil, err
		}
		cfg.WHPXProcessorClockFrequency = frequency
		defer worker.CloseFiles(targetPeer[:])
		closeAfterAck = append(closeAfterAck, assets.SharedRAM)
	}

	// Direct mode keeps the established slot table when networking is present.
	// Brokered mode inserts the peer pipe, shared RAM, and mailbox capabilities
	// before the optional network socket. Offline workers receive no socket.
	inherited := make([]worker.InheritedFile, 0, len(assetFiles)+cfg.VCPUs+7)
	netSlot, assetSlot := 7, 7
	if netFile != nil {
		assetSlot++
	}
	environment := vmmWorkerEnv()
	if cfg.WHPXBroker {
		inherited = append(inherited,
			worker.InheritedFile{Slot: 7, File: targetPeer[0]},
			worker.InheritedFile{Slot: 8, File: targetPeer[1]},
			worker.InheritedFile{Slot: 9, File: assets.SharedRAM},
			worker.InheritedFile{Slot: 10, File: mailboxes.Mapping},
			worker.InheritedFile{Slot: 11, File: mailboxes.RequestEvent},
		)
		for index, event := range mailboxes.ReplyEvents {
			inherited = append(inherited, worker.InheritedFile{Slot: 12 + index, File: event})
		}
		netSlot = 12 + cfg.VCPUs
		assetSlot = netSlot
		if netFile != nil {
			assetSlot++
		}
		environment = append(environment, "GANTRY_WINDOWS_WHPX_BROKER_ACTIVE=1")
	}
	if netFile != nil {
		inherited = append(inherited, worker.InheritedFile{Slot: netSlot, File: netFile})
	}
	for index, file := range assetFiles {
		inherited = append(inherited, worker.InheritedFile{Slot: assetSlot + index, File: file})
	}
	logPath := ""
	if dir != "" {
		logPath = filepath.Join(dir, "worker-vmm.log")
	}
	child, err := worker.Launch(worker.LaunchSpec{
		Role:             workerproto.RoleVMM,
		EntryPoint:       "_vmm-worker",
		Environment:      environment,
		Channels:         []string{"control", "bridge", "fd", "share"},
		InheritedFiles:   inherited,
		DiagnosticPath:   logPath,
		Confinement:      cfg.Confinement,
		ConfigureProcess: vmmWorkerSpawnHook,
	})
	if err != nil {
		if brokerChild != nil {
			_ = brokerChild.Terminate(5 * time.Second)
		}
		return nil, err
	}
	ctrlSup := child.Channels["control"]
	bridgeSup := child.Channels["bridge"]
	fdSup := workerproto.ForProcess(child.Channels["fd"], uint32(child.Process.Pid))
	shareSup := child.Channels["share"]

	var waitErr error
	killChild := func() {
		_ = child.Terminate(5 * time.Second)
		if brokerChild != nil {
			_ = brokerChild.Terminate(5 * time.Second)
		}
		waitErr = child.Err()
	}
	bootstrap, err := child.BeginBootstrap(cfg)
	if err != nil {
		killChild()
		return nil, fmt.Errorf("vmm worker handshake: %w", err)
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
	if assets.NetConn != nil {
		_ = assets.NetConn.Close()
	}
	if cfg.NoShares {
		_ = shareSup.Close()
		shareSup = nil
	}

	w := &vmmWorker{
		child: child, brokerChild: brokerChild, proc: child.Process,
		client: workerproto.NewClient(ctrlSup), fdChan: fdSup,
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

func spawnWHPXBroker(cfg vmmworkerapi.Config, sharedRAM *os.File, mailboxes vmm.WHPXMailboxFiles, dir string) (*worker.Child, [2]*os.File, uint64, error) {
	var empty [2]*os.File
	targetPeer, brokerPeer, err := worker.PipePairFiles()
	if err != nil {
		return nil, empty, 0, err
	}
	logPath := ""
	if dir != "" {
		logPath = filepath.Join(dir, "worker-whpx.log")
	}
	inherited := []worker.InheritedFile{
		{Slot: 4, File: sharedRAM},
		{Slot: 5, File: brokerPeer[0]},
		{Slot: 6, File: brokerPeer[1]},
		{Slot: 7, File: mailboxes.Mapping},
		{Slot: 8, File: mailboxes.RequestEvent},
	}
	for index, event := range mailboxes.ReplyEvents {
		inherited = append(inherited, worker.InheritedFile{Slot: 9 + index, File: event})
	}
	child, err := worker.Launch(worker.LaunchSpec{
		Role:             workerproto.RoleWHPX,
		EntryPoint:       "_whpx-worker",
		Environment:      vmmWorkerEnv(),
		Channels:         []string{"control"},
		InheritedFiles:   inherited,
		DiagnosticPath:   logPath,
		Confinement:      cfg.Confinement,
		ConfigureProcess: vmmWorkerSpawnHook,
	})
	worker.CloseFiles(brokerPeer[:])
	if err != nil {
		worker.CloseFiles(targetPeer[:])
		return nil, empty, 0, err
	}
	_, err = child.BeginBootstrap(vmm.WHPXBrokerConfig{
		MemSize: cfg.MemSize, VCPUs: cfg.VCPUs, PeerToken: cfg.WHPXToken,
	})
	if err != nil {
		_ = child.Terminate(5 * time.Second)
		worker.CloseFiles(targetPeer[:])
		return nil, empty, 0, fmt.Errorf("WHPX broker handshake: %w", err)
	}
	var ack vmm.WHPXBrokerBootAck
	control := child.Channels["control"]
	_ = control.SetReadDeadline(time.Now().Add(30 * time.Second))
	if err := workerproto.ReadMessage(control, &ack); err != nil {
		_ = child.Terminate(5 * time.Second)
		worker.CloseFiles(targetPeer[:])
		return nil, empty, 0, fmt.Errorf("WHPX broker boot ack: %w", err)
	}
	_ = control.SetReadDeadline(time.Time{})
	if !ack.OK {
		_ = child.Terminate(5 * time.Second)
		worker.CloseFiles(targetPeer[:])
		return nil, empty, 0, fmt.Errorf("WHPX broker boot: %s", ack.Error)
	}
	return child, targetPeer, ack.ProcessorClockFrequency, nil
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
		hostConn, err := net.DialTimeout("unix", socket, 3*time.Second)
		if err != nil {
			return nil, fmt.Errorf("vsock.forward %s: %w", socket, err)
		}
		// WSADuplicateSocket can reconstruct a Windows AF_UNIX socket in
		// another process, but on supported Server 2022 hosts that socket does
		// not reliably carry bytes after the source process closes its copy.
		// Transfer one end of a connected Winsock TCP pair instead and retain
		// all host-path/AF_UNIX authority in this supervisor relay.
		supervisor, target, err := worker.SocketpairConns()
		if err != nil {
			_ = hostConn.Close()
			return nil, fmt.Errorf("vsock.forward relay: %w", err)
		}
		file, err := worker.ConnFile(target)
		_ = target.Close()
		if err != nil {
			_ = supervisor.Close()
			_ = hostConn.Close()
			return nil, err
		}
		err = w.sendFD(token, file)
		_ = file.Close()
		if err != nil {
			_ = supervisor.Close()
			_ = hostConn.Close()
			return nil, fmt.Errorf("vsock.forward: %w", err)
		}
		go relayWindowsVsock(supervisor, hostConn)
		return nil, nil
	}
}

func relayWindowsVsock(left, right net.Conn) {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = left.Close()
			_ = right.Close()
		})
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(left, right)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(right, left)
		done <- struct{}{}
	}()
	<-done
	closeBoth()
	<-done
}
