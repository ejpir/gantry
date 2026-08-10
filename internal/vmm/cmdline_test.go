package vmm

import (
	"strings"
	"testing"
)

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
