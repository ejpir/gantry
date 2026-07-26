package vmm

// Platform asset defaults (nerdbox kernel/rootfs names, gvproxy binary name,
// and the nerdbox kernel cmdline mirrored from libkrun's instance.go).

import (
	"fmt"
	"net"
	"runtime"
	"strings"
)

// defaultKernelImage/defaultRootfs pick the nerdbox assets matching the
// host architecture (sbx ships nerdbox-{kernel,rootfs}-{arm64,x86_64}).
func DefaultKernelImage() string {
	if runtime.GOARCH == "amd64" {
		return "nerdbox-kernel-x86_64"
	}
	return "nerdbox-kernel-arm64"
}

func DefaultRootfs() string {
	if runtime.GOARCH == "amd64" {
		return "nerdbox-rootfs-x86_64.erofs"
	}
	return "nerdbox-rootfs-arm64.erofs"
}

// GvisorRootfs maps a rootfs image name to its gVisor variant (built by
// mkrootfs-gvisor.sh: /sbin/crun is runsc, real crun at /sbin/crun.runc).
func GvisorRootfs(p string) string {
	if strings.Contains(p, "rootfs-gvisor-") {
		return p
	}
	return strings.Replace(p, "rootfs-", "rootfs-gvisor-", 1)
}

// defaultGvproxy names the gvproxy binary for this platform (upstream
// gvisor-tap-vsock releases: gvproxy-{linux,darwin,windows}-{arch}).
func DefaultGvproxy() string {
	s := "gvproxy-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		s += ".exe"
	}
	return s
}

// defaultCmdline mirrors nerdbox's libkrun instance.go (PL011 on arm64,
// 16550 on x86 replaces virtio-console). Arguments after "--" configure
// vminitd.
func DefaultCmdline(arch, rootfsPath, initrdPath string, guestCID uint64, netEndpoint string, netMAC [6]byte, netDHCP bool) string {
	console := "console=ttyAMA0"
	if arch == "amd64" {
		console = "console=ttyS0"
	}
	switch {
	case rootfsPath != "" && initrdPath != "":
		// combo: kernel runs our init from the initramfs; it mounts the
		// attached rootfs at /mnt (no root= on purpose)
		return console + " panic=-1 nokaslr"
	case rootfsPath != "":
		cmdline := fmt.Sprintf("%s root=/dev/vda rootfstype=erofs ro nokaslr init=/sbin/vminitd -- -vsock-rpc-port=1025 -vsock-stream-port=1026 -vsock-cid=%d", console, guestCID)
		if netEndpoint != "" {
			cmdline += fmt.Sprintf(" -network=mac=%s", net.HardwareAddr(netMAC[:]))
			if netDHCP {
				cmdline += ",dhcp=true"
			}
		}
		return cmdline
	default:
		return console + " panic=-1 nokaslr"
	}
}
