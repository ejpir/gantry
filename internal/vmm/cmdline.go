package vmm

// Guest kernel command-line construction. Host-side artifact discovery and
// release staging live in internal/guestasset so the VMM remains concerned
// only with guest-machine configuration.

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/ejpir/gantry/internal/vmm/boot"
)

const windowsEagerSMPMemoryBytes = 8 << 30

// bootLogLevel caps kernel printk at KERN_WARNING on the console:
// every console byte crosses an MMIO exit round-trip through the VMM,
// and the ~10 KB of a verbose boot costs tens of ms of the in-guest
// boot time. Warnings and errors still land in console.log (so boot
// failures stay diagnosable), and vminitd's own stdout is unaffected
// (it writes /dev/console directly). GANTRY_DEBUG_BOOT=1 restores the
// full spew.
func bootLogLevel() string {
	if os.Getenv("GANTRY_DEBUG_BOOT") != "" {
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
// drops the sysctl set and explicitly disables allocation/free clearing — a
// bisect knob for guest boot problems. Zero-on-allocation remains enabled in
// production: it prevents stale kernel heap/page contents from reaching a new
// user. Zero-on-free is default-off because it duplicated that confidentiality
// guarantee at reuse time while adding about 80 ms to a 512 MiB arm64 HVF boot;
// GANTRY_STRICT_MEMORY_INIT=1 restores it as extra use-after-free hardening.
// Explicit values also override older Gantry kernels that compiled both
// INIT_ON_*_DEFAULT_ON options in.
func guestHardeningParams() string {
	if os.Getenv("GANTRY_NO_CMDLINE_HARDENING") != "" {
		return " init_on_alloc=0 init_on_free=0"
	}
	initOnFree := "0"
	if os.Getenv("GANTRY_STRICT_MEMORY_INIT") != "" {
		initOnFree = "1"
	}
	return " init_on_alloc=1 init_on_free=" + initOnFree +
		" sysctl.kernel.kptr_restrict=2" +
		" sysctl.kernel.dmesg_restrict=1" +
		" sysctl.kernel.unprivileged_bpf_disabled=1" +
		" sysctl.kernel.yama.ptrace_scope=1" +
		" sysctl.net.core.bpf_jit_harden=2"
}

// WithDeferredSMP asks Gantry's owned kernel to boot on CPU 0 and online the
// remaining CPUs after vminitd submits its first vsock packet. This keeps SMP
// RCU grace periods out of early filesystem/cgroup initialization while still
// making every configured CPU available as the control plane becomes ready.
//
// Large Windows guests are the exception. Linux initializes deferred struct
// pages before userspace, and WHPX measurements show that bringing configured
// CPUs up eagerly lets the kernel parallelize that RAM-proportional work. Set
// GANTRY_DEFER_SMP=1 (also accepts true, yes, and on) to force the old deferred
// behavior, or 0 (also false, no, and off) to force eager bringup. Stock and
// older kernels safely ignore the namespaced parameter.
func WithDeferredSMP(cmdline string, vcpus int, memBytes uint64) string {
	policyMemBytes := smpPolicyMemory(runtime.GOOS, memBytes, os.Getenv("GANTRY_VIRTIO_MEM"))
	if !shouldDeferSMP(runtime.GOOS, vcpus, policyMemBytes, os.Getenv("GANTRY_DEFER_SMP")) {
		return cmdline
	}
	separator := strings.Index(cmdline, " -- ")
	if separator < 0 || !strings.Contains(cmdline[:separator], "init=/sbin/vminitd") ||
		strings.Contains(cmdline[:separator], " gantry.defer_smp=") {
		return cmdline
	}
	return cmdline[:separator] + " gantry.defer_smp=1" + cmdline[separator:]
}

func smpPolicyMemory(hostOS string, memBytes uint64, virtioMemSetting string) uint64 {
	if hostOS == "windows" {
		if bootSize, enabled := boot.VirtioMemLayout(hostOS, memBytes, virtioMemSetting); enabled {
			// Only the boot region participates in early initialization. Let
			// the owned kernel bring the other CPUs online together with the
			// post-READY memory request triggered by the first vsock packet.
			return bootSize
		}
	}
	return memBytes
}

func shouldDeferSMP(hostOS string, vcpus int, memBytes uint64, setting string) bool {
	if vcpus <= 1 {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(setting)) {
	case "0", "false", "no", "off":
		return false
	case "1", "true", "yes", "on":
		return true
	}
	return hostOS != "windows" || memBytes < windowsEagerSMPMemoryBytes
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
