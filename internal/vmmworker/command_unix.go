//go:build linux || darwin

package vmmworker

import (
	"fmt"
	"net"
	"os"

	"github.com/ejpir/gantry/internal/workerproto"
)

const (
	// Fixed capability table inherited from the trusted supervisor. The
	// optional root and disk descriptors follow fdKernel in Config order.
	fdControl = 3
	fdBridge  = 4
	fdChannel = 5
	fdShare   = 6
	fdNet     = 7
	fdConsole = 8
	fdKernel  = 9
)

// Main reconstructs the inherited capability table and runs the hidden worker
// role. It is not a user-facing command.
func Main() int { return NewRuntime().Main() }

// Main runs the hidden worker role with this runtime. Keeping the runtime
// explicit lets process-boundary tests substitute a VM runner without global
// hooks in production code.
func (rt Runtime) Main() int {
	control, err := workerproto.InheritedConn(fdControl, "control")
	if err != nil {
		return commandError("control", err)
	}
	bridge, err := workerproto.InheritedConn(fdBridge, "bridge")
	if err != nil {
		_ = control.Close()
		return commandError("bridge", err)
	}
	fdChannel, err := workerproto.InheritedConn(fdChannel, "fd channel")
	if err != nil {
		_ = control.Close()
		_ = bridge.Close()
		return commandError("fd channel", err)
	}
	share, err := workerproto.InheritedConn(fdShare, "share channel")
	if err != nil {
		_ = control.Close()
		_ = bridge.Close()
		_ = fdChannel.Close()
		return commandError("share channel", err)
	}
	defer func() { _ = share.Close() }()

	load := func(config Config) (Assets, error) {
		return loadAssets(config, share)
	}
	if err := rt.Serve(control, bridge, fdChannel, load); err != nil {
		fmt.Fprintln(os.Stderr, "_vmm-worker:", err)
		return 1
	}
	return 0
}

func commandError(channel string, err error) int {
	fmt.Fprintf(os.Stderr, "vmm worker %s: %v\n", channel, err)
	return 2
}

func loadAssets(config Config, share net.Conn) (Assets, error) {
	assets := Assets{ShareConn: share}
	slot := fdNet
	next := func(name string) *os.File {
		file := os.NewFile(uintptr(slot), name)
		slot++
		return file
	}

	netFile := next("net")
	if netFile == nil {
		return assets, fmt.Errorf("net: missing descriptor")
	}
	netConn, err := net.FileConn(netFile)
	_ = netFile.Close()
	if err != nil {
		return assets, fmt.Errorf("net: %w", err)
	}
	assets.NetConn = netConn

	assets.Console = next("console")
	assets.Kernel = next("kernel")
	if assets.Console == nil || assets.Kernel == nil {
		return assets, fmt.Errorf("console or kernel: missing descriptor")
	}
	if config.HasRoot {
		assets.Rootfs = next("rootfs")
		if assets.Rootfs == nil {
			return assets, fmt.Errorf("rootfs: missing descriptor")
		}
	}
	assets.DisksRO = make([]*os.File, 0, config.NDisksRO)
	for index := 0; index < config.NDisksRO; index++ {
		file := next(fmt.Sprintf("disk-ro-%d", index))
		if file == nil {
			return assets, fmt.Errorf("disk-ro-%d: missing descriptor", index)
		}
		assets.DisksRO = append(assets.DisksRO, file)
	}
	assets.Disks = make([]*os.File, 0, config.NDisks)
	for index := 0; index < config.NDisks; index++ {
		file := next(fmt.Sprintf("disk-%d", index))
		if file == nil {
			return assets, fmt.Errorf("disk-%d: missing descriptor", index)
		}
		assets.Disks = append(assets.Disks, file)
	}
	if config.HasSharedRAM {
		assets.SharedRAM = next("shared-ram")
		if assets.SharedRAM == nil {
			return assets, fmt.Errorf("shared RAM: missing descriptor")
		}
		assets.VhostQueue = make([]VhostQueueFiles, VhostQueueCount)
		for index := range assets.VhostQueue {
			assets.VhostQueue[index] = VhostQueueFiles{
				KickRead:  next(fmt.Sprintf("vhost-kick-read-%d", index)),
				KickWrite: next(fmt.Sprintf("vhost-kick-write-%d", index)),
				CallRead:  next(fmt.Sprintf("vhost-call-read-%d", index)),
				CallWrite: next(fmt.Sprintf("vhost-call-write-%d", index)),
			}
		}
	}
	if config.HasKVM {
		assets.KVM = next("kvm")
		if assets.KVM == nil {
			return assets, fmt.Errorf("kvm: missing descriptor")
		}
	}
	return assets, nil
}
