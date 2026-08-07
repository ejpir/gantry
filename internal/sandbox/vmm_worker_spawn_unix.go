//go:build linux || darwin

package sandbox

// _vmm-worker spawn (supervisor side) and entry point (worker side).
//
// Descriptor table handed to the child (fixed slots; everything after
// the console is a boot asset in config-defined order):
//
//	0,1,2  std
//	3      control      (workerproto RPC, supervisor -> worker)
//	4      bridge       (workerproto RPC, worker -> supervisor)
//	5      fd channel   (SCM_RIGHTS, nonce first)
//	6      net data     (QEMU-framed Ethernet)
//	7      console log
//	8      kernel
//	9      rootfs (when cfg.HasRoot)
//	...    DisksRO, Disks, share roots

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ejpir/gantry/internal/workerproto"
)

const (
	vmmFDControl = 3
	vmmFDBridge  = 4
	vmmFDChannel = 5
	vmmFDNet     = 6
	vmmFDConsole = 7
	vmmFDKernel  = 8
)

// spawnVMMWorker re-execs the binary as _vmm-worker with the descriptor
// table and performs the handshake + nonce exchange. cfg counts must
// match the assets (HasRoot ↔ Rootfs, NDisksRO/NDisks, Shares ↔
// ShareRoots) — the worker validates too, but failing here keeps the
// error local.
func spawnVMMWorker(cfg vmmBootConfig, assets vmmWorkerAssets, dir string) (*vmmWorker, error) {
	ctrlSup, ctrlWrk, err := socketpairConns()
	if err != nil {
		return nil, err
	}
	bridgeSup, bridgeWrk, err := socketpairConns()
	if err != nil {
		return nil, err
	}
	fdSup, fdWrk, err := socketpairConns()
	if err != nil {
		return nil, err
	}
	// The child duplicates each end into its table slot; the originals
	// close after spawn. dupFiles are supervisor-side duplicates (always
	// closed here); assetFiles are the SUPERVISOR'S OWN copies of the
	// boot assets — closed only after a fully successful handshake, so a
	// failed spawn can degrade to monolithic with the assets intact.
	var dupFiles []*os.File
	for _, c := range []net.Conn{ctrlWrk, bridgeWrk, fdWrk} {
		f, err := connFile(c)
		_ = c.Close()
		if err != nil {
			return nil, err
		}
		dupFiles = append(dupFiles, f)
	}
	closeDups := func() {
		for _, f := range dupFiles {
			_ = f.Close()
		}
	}
	if assets.NetConn == nil || assets.Console == nil || assets.Kernel == nil {
		closeDups()
		return nil, fmt.Errorf("descriptor table: net conn, console and kernel are required")
	}
	// The net data end is dup'd into the child's slot; the supervisor
	// keeps no copy (the channel belongs to the two workers).
	netFile, err := connFile(assets.NetConn)
	if err != nil {
		closeDups()
		return nil, err
	}
	_ = assets.NetConn.Close()
	dupFiles = append(dupFiles, netFile)
	assetFiles := []*os.File{assets.Console, assets.Kernel}
	if cfg.HasRoot {
		if assets.Rootfs == nil {
			closeDups()
			return nil, fmt.Errorf("descriptor table: rootfs required")
		}
		assetFiles = append(assetFiles, assets.Rootfs)
	}
	if len(assets.DisksRO) != cfg.NDisksRO || len(assets.Disks) != cfg.NDisks || len(assets.ShareRoots) != len(cfg.Shares) {
		closeDups()
		return nil, fmt.Errorf("descriptor table: counts mismatch (disksRO %d/%d, disks %d/%d, shares %d/%d)",
			len(assets.DisksRO), cfg.NDisksRO, len(assets.Disks), cfg.NDisks, len(assets.ShareRoots), len(cfg.Shares))
	}
	assetFiles = append(assetFiles, assets.DisksRO...)
	assetFiles = append(assetFiles, assets.Disks...)
	assetFiles = append(assetFiles, assets.ShareRoots...)
	childFiles := append(append([]*os.File{}, dupFiles...), assetFiles...)

	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("worker re-exec path: %w", err)
	}
	argv := []string{exe, "_vmm-worker"}
	env := workerEnv()
	if vmmWorkerSpawnHook != nil {
		vmmWorkerSpawnHook(&argv, &env)
	}
	procFiles := append([]*os.File{os.Stdin, os.Stdout, os.Stderr}, childFiles...)
	proc, err := os.StartProcess(exe, argv, &os.ProcAttr{
		Env:   env,
		Files: procFiles,
		Sys:   workerSysProcAttr(),
	})
	closeDups() // the child has its own table entries now
	if err != nil {
		_ = ctrlSup.Close()
		_ = bridgeSup.Close()
		_ = fdSup.Close()
		return nil, fmt.Errorf("spawn vmm worker: %w", err)
	}

	killProc := func() {
		_ = proc.Kill()
		_, _ = proc.Wait()
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		killProc()
		return nil, err
	}
	if err := workerproto.SendHandshake(ctrlSup, workerproto.RoleVMM, nonce, cfg); err != nil {
		killProc()
		return nil, fmt.Errorf("vmm worker handshake: %w", err)
	}
	if err := workerproto.WriteNonce(fdSup, nonce); err != nil {
		killProc()
		return nil, fmt.Errorf("vmm worker nonce: %w", err)
	}
	// Boot ack: the worker answers after Prepare (machine built) — a
	// missing /dev/kvm or a bad asset surfaces HERE, not as a dead VM
	// minutes later.
	var ack struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = ctrlSup.SetReadDeadline(time.Now().Add(60 * time.Second))
	if err := workerproto.ReadMessage(ctrlSup, &ack); err != nil {
		killProc()
		return nil, fmt.Errorf("vmm worker boot ack: %w", err)
	}
	_ = ctrlSup.SetReadDeadline(time.Time{})
	if !ack.OK {
		killProc()
		return nil, fmt.Errorf("vmm worker boot: %s", ack.Error)
	}
	// Handshake complete: the worker owns the boot assets now; close the
	// supervisor's copies (the descriptor table carried them across).
	for _, f := range assetFiles {
		_ = f.Close()
	}

	w := &vmmWorker{
		proc:    proc,
		client:  workerproto.NewClient(ctrlSup),
		fdChan:  fdSup,
		bridge:  bridgeSup,
		bridgeE: make(chan error, 1),
		dead:    make(chan struct{}),
	}
	go func() {
		w.bridgeE <- workerproto.ServeRequests(bridgeSup, map[string]workerproto.Handler{
			"vsock.forward": w.vsockForward(dir),
		})
	}()
	go func() {
		_, err := proc.Wait()
		w.setDead(err)
	}()
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
		var body vsockForwardRequest
		if err := json.Unmarshal(req.Body, &body); err != nil {
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

// ------------------------------------------------------------ worker main

// CmdVMMWorker is the _vmm-worker entry point: reconstruct the descriptor
// table and run the worker. Never invoked by users; launched by
// spawnVMMWorker.
func CmdVMMWorker() int {
	control, err := inheritedConn(vmmFDControl, "control")
	if err != nil {
		fmt.Fprintln(os.Stderr, "vmm worker control:", err)
		return 2
	}
	bridge, err := inheritedConn(vmmFDBridge, "bridge")
	if err != nil {
		fmt.Fprintln(os.Stderr, "vmm worker bridge:", err)
		return 2
	}
	fdChan, err := inheritedConn(vmmFDChannel, "fd channel")
	if err != nil {
		fmt.Fprintln(os.Stderr, "vmm worker fd channel:", err)
		return 2
	}
	assetsFn := func(cfg vmmBootConfig) (vmmWorkerAssets, error) {
		var a vmmWorkerAssets
		slot := vmmFDNet
		next := func(what string) (*os.File, error) {
			f := os.NewFile(uintptr(slot), what)
			slot++
			if f == nil {
				return nil, fmt.Errorf("%s: missing descriptor", what)
			}
			return f, nil
		}
		netFile, err := next("net")
		if err != nil {
			return a, err
		}
		a.NetConn, err = net.FileConn(netFile)
		_ = netFile.Close()
		if err != nil {
			return a, fmt.Errorf("net: %w", err)
		}
		if a.Console, err = next("console"); err != nil {
			return a, err
		}
		if a.Kernel, err = next("kernel"); err != nil {
			return a, err
		}
		if cfg.HasRoot {
			if a.Rootfs, err = next("rootfs"); err != nil {
				return a, err
			}
		}
		for i := 0; i < cfg.NDisksRO; i++ {
			f, err := next(fmt.Sprintf("disk-ro-%d", i))
			if err != nil {
				return a, err
			}
			a.DisksRO = append(a.DisksRO, f)
		}
		for i := 0; i < cfg.NDisks; i++ {
			f, err := next(fmt.Sprintf("disk-%d", i))
			if err != nil {
				return a, err
			}
			a.Disks = append(a.Disks, f)
		}
		for i := range cfg.Shares {
			f, err := next("share-" + cfg.Shares[i].Tag)
			if err != nil {
				return a, err
			}
			a.ShareRoots = append(a.ShareRoots, f)
		}
		return a, nil
	}
	if err := runVMMWorker(control, bridge, fdChan, assetsFn); err != nil {
		fmt.Fprintln(os.Stderr, "vmm worker:", err)
		return 1
	}
	return 0
}
