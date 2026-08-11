package vmm

import (
	"strings"
	"testing"
)

func TestWithDeferredSMP(t *testing.T) {
	base := DefaultCmdline("arm64", "/x/rootfs.erofs", "", 3, "", [6]byte{}, false)

	if got := WithDeferredSMP(base, 1); got != base {
		t.Fatalf("single-vCPU cmdline changed:\n%s", got)
	}
	got := WithDeferredSMP(base, 8)
	parameter := strings.Index(got, " gantry.defer_smp=1")
	separator := strings.Index(got, " -- ")
	if parameter < 0 || separator < 0 || parameter > separator {
		t.Fatalf("deferred-SMP parameter is not a kernel argument:\n%s", got)
	}

	t.Setenv("GANTRY_DEFER_SMP", "off")
	if got := WithDeferredSMP(base, 8); got != base {
		t.Fatalf("GANTRY_DEFER_SMP=off did not retain eager bringup:\n%s", got)
	}

	t.Setenv("GANTRY_DEFER_SMP", "")
	debug := DefaultCmdline("arm64", "/x/rootfs.erofs", "/x/initrd", 3, "", [6]byte{}, false)
	if got := WithDeferredSMP(debug, 8); got != debug {
		t.Fatalf("initramfs debug cmdline unexpectedly deferred SMP:\n%s", got)
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
