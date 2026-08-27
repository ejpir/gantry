//go:build linux || darwin

package vmmworker

// Trusted-side process creation and host-socket brokering for _vmm-worker.
// The inherited descriptor table is the worker's complete capability set.

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/worker"
	vmmworkerapi "github.com/ejpir/gantry/internal/vmmworker"
	"github.com/ejpir/gantry/internal/workerproto"
)

// spawnVMMWorker validates and prepares the role-specific VMM assets, then
// delegates re-exec, channels, diagnostics, confinement, and process watching
// to the generic worker launch harness.
func spawnVMMWorker(cfg vmmworkerapi.Config, assets vmmworkerapi.Assets, dir string) (*vmmWorker, error) {
	if assets.NetConn == nil || assets.Console == nil || assets.Kernel == nil {
		return nil, fmt.Errorf("descriptor table: net conn, console and kernel are required")
	}
	consoleInfo, err := assets.Console.Stat()
	if err != nil {
		return nil, fmt.Errorf("descriptor table: inspect console sink: %w", err)
	}
	if consoleInfo.Mode()&os.ModeNamedPipe == 0 {
		return nil, fmt.Errorf("descriptor table: console must be a supervisor-brokered pipe, got mode %s", consoleInfo.Mode())
	}

	// Keep the caller's original endpoint open until the boot ack so auto mode
	// can reuse it for the monolithic fallback. Launch inherits only this dup.
	netFile, err := worker.ConnFile(assets.NetConn)
	if err != nil {
		return nil, err
	}
	defer func() { _ = netFile.Close() }()

	assetFiles := []*os.File{assets.Console, assets.Kernel}
	closeAfterAck := append([]*os.File(nil), assetFiles...)
	if cfg.HasRoot {
		if assets.Rootfs == nil {
			return nil, fmt.Errorf("descriptor table: rootfs required")
		}
		assetFiles = append(assetFiles, assets.Rootfs)
		closeAfterAck = append(closeAfterAck, assets.Rootfs)
	}
	if len(assets.DisksRO) != cfg.NDisksRO || len(assets.Disks) != cfg.NDisks {
		return nil, fmt.Errorf("descriptor table: counts mismatch (disksRO %d/%d, disks %d/%d)",
			len(assets.DisksRO), cfg.NDisksRO, len(assets.Disks), cfg.NDisks)
	}
	assetFiles = append(assetFiles, assets.DisksRO...)
	closeAfterAck = append(closeAfterAck, assets.DisksRO...)

	// Keep writable host files and their private locks in the trusted
	// supervisor. Each inherited slot is a fixed-size disk-broker stream, not
	// a file descriptor, so differently sized workload and IDE layers cannot
	// be grown by a compromised VMM worker.
	var (
		diskLocks     []*os.File
		diskRelays    []*diskRelay
		diskPeerConns []net.Conn
		diskPeerFiles []*os.File
	)
	keepDiskCapabilities := false
	defer func() {
		for _, conn := range diskPeerConns {
			_ = conn.Close()
		}
		worker.CloseFiles(diskPeerFiles)
		if !keepDiskCapabilities {
			for _, relay := range diskRelays {
				_ = relay.Close()
			}
			worker.CloseFiles(diskLocks)
		}
	}()
	cfg.WritableDiskSizes = make([]uint64, 0, len(assets.Disks))
	for index, disk := range assets.Disks {
		if disk == nil {
			return nil, fmt.Errorf("descriptor table: writable disk %d is nil", index)
		}
		lock, err := lockDiskForRelay(disk)
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
		size := uint64(info.Size())
		relay, peer, err := newDiskRelay(lock, size)
		if err != nil {
			return nil, err
		}
		diskRelays = append(diskRelays, relay)
		diskPeerConns = append(diskPeerConns, peer)
		peerFile, err := worker.ConnFile(peer)
		if err != nil {
			return nil, fmt.Errorf("writable disk %d broker descriptor: %w", index, err)
		}
		diskPeerFiles = append(diskPeerFiles, peerFile)
		assetFiles = append(assetFiles, peerFile)
		cfg.WritableDiskSizes = append(cfg.WritableDiskSizes, size)
	}
	if len(assets.Disks) != 0 {
		cfg.DisksBrokered = true
	}
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

	// Four generic channels occupy fds 3..6. VMM capabilities remain a dense,
	// role-validated table beginning with the network endpoint at fd 7.
	childFiles := append([]*os.File{netFile}, assetFiles...)
	inherited := make([]worker.InheritedFile, 0, len(childFiles))
	for index, file := range childFiles {
		inherited = append(inherited, worker.InheritedFile{Slot: 7 + index, File: file})
	}
	exitClosers := make([]io.Closer, 0, len(diskLocks)+len(diskRelays))
	// Stop and sync every broker before releasing its exclusive disk lock.
	for _, relay := range diskRelays {
		exitClosers = append(exitClosers, relay)
	}
	for _, lock := range diskLocks {
		exitClosers = append(exitClosers, lock)
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
		ExitClosers:      exitClosers,
		ConfigureProcess: vmmWorkerSpawnHook,
	})
	if err != nil {
		return nil, err
	}
	keepDiskCapabilities = true // Child now revokes locks and relays on every exit path.

	ctrlSup := child.Channels["control"]
	bridgeSup := child.Channels["bridge"]
	fdSup := child.Channels["fd"]
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
	if err := bootstrap.BindChannels("fd", "share"); err != nil {
		killChild()
		return nil, fmt.Errorf("vmm worker channel nonce: %w", err)
	}

	// Boot ack commits asset ownership only after VMM preparation and
	// confinement verification complete.
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
		child:      child,
		proc:       child.Process,
		client:     workerproto.NewClient(ctrlSup),
		fdChan:     fdSup,
		bridge:     bridgeSup,
		bridgeE:    make(chan error, 1),
		share:      shareSup,
		diskE:      make(chan error, max(1, len(diskRelays))),
		lifecycle:  child.Lifecycle,
		confReport: ack.Confinement,
	}
	for index, relay := range diskRelays {
		go w.monitorDiskRelay(relay, index)
	}
	go func() {
		w.bridgeE <- workerproto.ServeRequests(bridgeSup, map[string]workerproto.Handler{
			"vsock.forward": w.vsockForward(dir),
		})
	}()
	go w.observeChild()
	return w, nil
}

// vsockForward answers the worker's dial-back bridge: the guest connected
// to a vsock port; the supervisor validates and dials the sandbox endpoint,
// then transfers only the connected descriptor.
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
		file, err := worker.ConnFile(conn)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		err = w.sendFD(tok, file)
		_ = file.Close()
		_ = conn.Close()
		if err != nil {
			return nil, fmt.Errorf("vsock.forward: %w", err)
		}
		return nil, nil
	}
}
