package vmm

import (
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/vmm/boot"
)

func TestWithDeferredSMP(t *testing.T) {
	base := DefaultCmdline("arm64", "/x/rootfs.erofs", "", 3, "", [6]byte{}, false)

	if got := WithDeferredSMP(base, 1, 512<<20); got != base {
		t.Fatalf("single-vCPU cmdline changed:\n%s", got)
	}
	got := WithDeferredSMP(base, 8, 512<<20)
	parameter := strings.Index(got, " gantry.defer_smp=1")
	separator := strings.Index(got, " -- ")
	if parameter < 0 || separator < 0 || parameter > separator {
		t.Fatalf("deferred-SMP parameter is not a kernel argument:\n%s", got)
	}

	t.Setenv("GANTRY_DEFER_SMP", "off")
	if got := WithDeferredSMP(base, 8, 512<<20); got != base {
		t.Fatalf("GANTRY_DEFER_SMP=off did not retain eager bringup:\n%s", got)
	}

	t.Setenv("GANTRY_DEFER_SMP", "")
	debug := DefaultCmdline("arm64", "/x/rootfs.erofs", "/x/initrd", 3, "", [6]byte{}, false)
	if got := WithDeferredSMP(debug, 8, 512<<20); got != debug {
		t.Fatalf("initramfs debug cmdline unexpectedly deferred SMP:\n%s", got)
	}
}

func TestWindowsLargeMemoryUsesEagerSMP(t *testing.T) {
	tests := []struct {
		name     string
		hostOS   string
		vcpus    int
		memBytes uint64
		setting  string
		want     bool
	}{
		{name: "windows below threshold", hostOS: "windows", vcpus: 4, memBytes: windowsEagerSMPMemoryBytes - 1, want: true},
		{name: "windows at threshold", hostOS: "windows", vcpus: 4, memBytes: windowsEagerSMPMemoryBytes, want: false},
		{name: "linux large guest", hostOS: "linux", vcpus: 4, memBytes: 22 << 30, want: true},
		{name: "forced deferred", hostOS: "windows", vcpus: 4, memBytes: 22 << 30, setting: "on", want: true},
		{name: "forced eager", hostOS: "linux", vcpus: 4, memBytes: 512 << 20, setting: "off", want: false},
		{name: "single CPU", hostOS: "windows", vcpus: 1, memBytes: 22 << 30, setting: "on", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldDeferSMP(test.hostOS, test.vcpus, test.memBytes, test.setting); got != test.want {
				t.Fatalf("shouldDeferSMP(%q, %d, %d, %q) = %v, want %v", test.hostOS, test.vcpus, test.memBytes, test.setting, got, test.want)
			}
		})
	}
}

func TestVirtioMemUsesBootRegionForDeferredSMPPolicy(t *testing.T) {
	const total = uint64(22 << 30)
	policyMemory := smpPolicyMemory("windows", total, "")
	if policyMemory != boot.VirtioMemBootSize {
		t.Fatalf("SMP policy memory = %d MiB, want %d MiB", policyMemory>>20, boot.VirtioMemBootSize>>20)
	}
	if !shouldDeferSMP("windows", 4, policyMemory, "") {
		t.Fatal("small virtio-mem boot region should retain deferred SMP")
	}
}

func TestDefaultCmdlineHardening(t *testing.T) {
	cmd := DefaultCmdline("arm64", "/x/rootfs.erofs", "", 3, "", [6]byte{}, false)
	for _, want := range []string{
		"init_on_alloc=1", "init_on_free=0",
		"sysctl.kernel.kptr_restrict=2", "sysctl.kernel.dmesg_restrict=1",
		"sysctl.kernel.unprivileged_bpf_disabled=1",
		"sysctl.kernel.yama.ptrace_scope=1",
		"sysctl.net.core.bpf_jit_harden=2",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("production cmdline lacks %q:\n%s", want, cmd)
		}
	}
	if strings.Contains(cmd, "kexec") {
		t.Errorf("cmdline carries kexec sysctl noise:\n%s", cmd)
	}

	t.Setenv("GANTRY_STRICT_MEMORY_INIT", "1")
	strict := DefaultCmdline("arm64", "/x/rootfs.erofs", "", 3, "", [6]byte{}, false)
	if !strings.Contains(strict, "init_on_alloc=1") || !strings.Contains(strict, "init_on_free=1") {
		t.Errorf("strict cmdline lacks memory initialization:\n%s", strict)
	}
	t.Setenv("GANTRY_STRICT_MEMORY_INIT", "")

	t.Setenv("GANTRY_NO_CMDLINE_HARDENING", "1")
	off := DefaultCmdline("arm64", "/x/rootfs.erofs", "", 3, "", [6]byte{}, false)
	if strings.Contains(off, "sysctl.") || !strings.Contains(off, "init_on_alloc=0") || !strings.Contains(off, "init_on_free=0") {
		t.Errorf("disabled cmdline still hardened:\n%s", off)
	}
	debug := DefaultCmdline("arm64", "/x/rootfs.erofs", "/x/initrd", 3, "", [6]byte{}, false)
	if strings.Contains(debug, "sysctl.") {
		t.Errorf("debug cmdline carries hardening sysctls:\n%s", debug)
	}
}

func TestInsertKernelArgs(t *testing.T) {
	got := insertKernelArgs("console=ttyS0 ro -- -vsock-cid=3", "virtio_mmio.device=0x1000@0xc0000000:3")
	want := "console=ttyS0 ro virtio_mmio.device=0x1000@0xc0000000:3 -- -vsock-cid=3"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if got := insertKernelArgs("console=ttyS0", "a=b"); got != "console=ttyS0 a=b" {
		t.Errorf("no-separator case: %q", got)
	}
}

func TestKernelArgPresent(t *testing.T) {
	cmdline := "console=ttyS0 tsc_early_khz=2900000 -- tsc_early_khz=guest-flag"
	if !kernelArgPresent(cmdline, "tsc_early_khz") {
		t.Fatal("kernelArgPresent missed an assigned kernel argument")
	}
	if kernelArgPresent("console=ttyS0 -- tsc_early_khz=2900000", "tsc_early_khz") {
		t.Fatal("kernelArgPresent inspected arguments after --")
	}
	if kernelArgPresent("console=ttyS0 notsc_early_khz=1", "tsc_early_khz") {
		t.Fatal("kernelArgPresent accepted a suffix match")
	}
}
