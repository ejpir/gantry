package vmmworker

import (
	"fmt"
	"net"
	"os"

	"github.com/ejpir/gantry/internal/workerproto"
)

const (
	winControl = 3
	winBridge  = 4
	winChannel = 5
	winShare   = 6
	winNet     = 7
	winConsole = 8
	winKernel  = 9
)

func Main() int { return NewRuntime().Main() }

func (rt Runtime) Main() int {
	control, err := workerproto.InheritedConn(winControl, "control")
	if err != nil {
		return commandError("control", err)
	}
	bridge, err := workerproto.InheritedConn(winBridge, "bridge")
	if err != nil {
		_ = control.Close()
		return commandError("bridge", err)
	}
	fdChannel, err := workerproto.InheritedConn(winChannel, "socket channel")
	if err != nil {
		_ = control.Close()
		_ = bridge.Close()
		return commandError("socket channel", err)
	}
	share, err := workerproto.InheritedConn(winShare, "share channel")
	if err != nil {
		_ = control.Close()
		_ = bridge.Close()
		_ = fdChannel.Close()
		return commandError("share channel", err)
	}
	defer func() { _ = share.Close() }()

	load := func(config Config) (Assets, error) { return loadWindowsAssets(config, share, fdChannel) }
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

func loadWindowsAssets(config Config, share, fdChannel net.Conn) (Assets, error) {
	assets := Assets{ShareConn: share}
	slot := uintptr(winConsole)
	next := func(name string) *os.File {
		file, err := workerproto.InheritedFile(slot, name)
		slot++
		if err != nil {
			return nil
		}
		return file
	}

	_, netFile, err := workerproto.RecvFD(fdChannel)
	if err != nil {
		return assets, fmt.Errorf("net: receive socket: %w", err)
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
		return assets, fmt.Errorf("console or kernel: missing inherited handle")
	}
	if config.HasRoot {
		assets.Rootfs = next("rootfs")
		if assets.Rootfs == nil {
			return assets, fmt.Errorf("rootfs: missing inherited handle")
		}
	}
	assets.DisksRO = make([]*os.File, 0, config.NDisksRO)
	for index := 0; index < config.NDisksRO; index++ {
		file := next(fmt.Sprintf("disk-ro-%d", index))
		if file == nil {
			return assets, fmt.Errorf("disk-ro-%d: missing inherited handle", index)
		}
		assets.DisksRO = append(assets.DisksRO, file)
	}
	assets.Disks = make([]*os.File, 0, config.NDisks)
	for index := 0; index < config.NDisks; index++ {
		file := next(fmt.Sprintf("disk-%d", index))
		if file == nil {
			return assets, fmt.Errorf("disk-%d: missing inherited handle", index)
		}
		assets.Disks = append(assets.Disks, file)
	}
	if config.HasSharedRAM || config.HasKVM {
		return assets, fmt.Errorf("shared RAM and KVM handles are unavailable with WHPX")
	}
	return assets, nil
}
