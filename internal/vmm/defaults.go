package vmm

// Platform asset defaults (nerdbox kernel/rootfs names, gvproxy binary name,
// and the nerdbox kernel cmdline mirrored from libkrun's instance.go).

import (
	"fmt"
	"gantry/internal/gutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// AssetPath returns the repository's conventional path for a generated
// guest asset. Artifacts live in ./artifacts in a checkout, while the bare
// name remains a compatibility fallback for callers that stage assets in
// their working directory (and for tests).
func AssetPath(name string) string {
	if dir := os.Getenv("GANTRY_ARTIFACTS"); dir != "" {
		return filepath.Join(dir, name)
	}
	candidate := filepath.Join("artifacts", name)
	if gutil.FileExists(candidate) {
		return candidate
	}
	return name
}

// defaultKernelImage picks Gantry's own hardened kernel (built by
// scripts/mkkernel.sh, or downloaded from the release page by
// EnsureKernel) when staged, falling back to the stock nerdbox kernel
// when that is what the user has. When neither exists the gantry-kernel
// path is returned anyway: Resolve downloads it on demand.
func DefaultKernelImage() string {
	gantry, nerdbox := "gantry-kernel-arm64", "nerdbox-kernel-arm64"
	if runtime.GOARCH == "amd64" {
		gantry, nerdbox = "gantry-kernel-x86_64", "nerdbox-kernel-x86_64"
	}
	if p := AssetPath(gantry); gutil.FileExists(p) {
		return p
	}
	if p := AssetPath(nerdbox); gutil.FileExists(p) {
		return p
	}
	return AssetPath(gantry)
}

func DefaultRootfs() string {
	if runtime.GOARCH == "amd64" {
		return AssetPath("nerdbox-rootfs-x86_64.erofs")
	}
	return AssetPath("nerdbox-rootfs-arm64.erofs")
}

// DefaultImage picks the full Debian image when it is staged, otherwise the
// small debug image. Both are generated artifacts rather than source files.
func DefaultImage() string {
	if p := AssetPath("debian-bookworm.erofs"); gutil.FileExists(p) {
		return p
	}
	return AssetPath("shell-rootfs.erofs")
}

// GvisorRootfs maps a rootfs image name to its gVisor variant (built by
// mkrootfs-gvisor.sh: /sbin/crun is runsc, real crun at /sbin/crun.runc).
func GvisorRootfs(p string) string {
	if strings.Contains(p, "rootfs-gvisor-") {
		return p
	}
	return strings.Replace(p, "rootfs-", "rootfs-gvisor-", 1)
}

// GvisorKernel maps an arm64 kernel image name to its 4K-page variant
// (built by mkkernel-4k.sh). Stock nerdbox arm64 kernels use 16K pages,
// which gVisor's stock runsc refuses to boot on. x86_64 is always 4K.
func GvisorKernel(p string) string {
	if runtime.GOARCH != "arm64" || strings.HasSuffix(p, "-4k") {
		return p
	}
	return p + "-4k"
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

// bootLogLevel caps kernel printk at KERN_WARNING on the console:
// every console byte crosses an MMIO exit round-trip through the VMM,
// and the ~10 KB of a verbose boot costs tens of ms of the in-guest
// boot time. Warnings and errors still land in console.log (so boot
// failures stay diagnosable), and vminitd's own stdout is unaffected
// (it writes /dev/console directly). GANTRY_DEBUG_BOOT=1 restores the
// full spew.
func bootLogLevel() string {
	if gutil.EnvOr("GANTRY_DEBUG_BOOT") != "" {
		return ""
	}
	return " loglevel=4"
}

// guestHardeningParams hardens whatever kernel boots — stock nerdbox or
// gantry's own — via boot parameters and early sysctl settings (supported
// since Linux 5.8; unknown keys are dropped with a printk, so a kernel
// lacking YAMA simply ignores that line). vminitd never overwrites these
// sysctls. KEXEC is not covered here: both supported kernels compile it
// out, so the sysctl would only print "parameter not found" (the dev
// guest init sets it silently instead). GANTRY_NO_CMDLINE_HARDENING=1
// drops the whole set — a bisect knob for guest boot problems.
func guestHardeningParams() string {
	if gutil.EnvOr("GANTRY_NO_CMDLINE_HARDENING") != "" {
		return ""
	}
	return " init_on_alloc=1 init_on_free=1" +
		" sysctl.kernel.kptr_restrict=2" +
		" sysctl.kernel.dmesg_restrict=1" +
		" sysctl.kernel.unprivileged_bpf_disabled=1" +
		" sysctl.kernel.yama.ptrace_scope=1" +
		" sysctl.net.core.bpf_jit_harden=2"
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
		// attached rootfs at /mnt (no root= on purpose). Debug shells:
		// keep the full boot spew.
		return console + " panic=-1 nokaslr"
	case rootfsPath != "":
		cmdline := fmt.Sprintf("%s%s%s root=/dev/vda rootfstype=erofs ro nokaslr init=/sbin/vminitd -- -vsock-rpc-port=1025 -vsock-stream-port=1026 -vsock-cid=%d", console, bootLogLevel(), guestHardeningParams(), guestCID)
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
