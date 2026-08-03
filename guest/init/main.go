//go:build linux

// Guest PID 1 for gantry — a static aarch64 Go binary, like nerdbox's
// vminitd but minimal: mount filesystems, say hello, run a shell on the
// serial console, then power off via PSCI (which our VMM turns into a
// clean exit).
//
// Mount hardening mirrors nerdbox's vminitd (docs/hardening-audit.md
// layer 4): every pseudo-fs is nosuid/noexec/nodev, /tmp gets the same,
// cgroup2 is mounted with subtree-control delegation, and the sysctls
// below match the ones DefaultCmdline sets for production vminitd boots
// (this init also serves bare-kernel debug boots whose cmdline lacks
// them). All of it is best-effort: a kernel without YAMA or cgroup2
// still boots the dev shell.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func mount(src, target, fstype string, flags uintptr) {
	if err := syscall.Mount(src, target, fstype, flags, ""); err != nil && err != syscall.EBUSY {
		fmt.Printf("[init] mount %s: %v\n", target, err)
	}
}

// sysctl writes key=value under /proc/sys, silently skipping sysctls the
// kernel does not have (e.g. kernel.yama.ptrace_scope without CONFIG_YAMA).
func sysctl(key, value string) {
	p := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	if err := os.WriteFile(p, []byte(value), 0o644); err != nil && !os.IsNotExist(err) {
		fmt.Printf("[init] sysctl %s=%s: %v\n", key, value, err)
	}
}

// mountCgroups mounts cgroup2 and delegates the controllers crun needs to
// nested cgroups, matching what vminitd does for production sandboxes.
func mountCgroups() {
	if err := os.MkdirAll("/sys/fs/cgroup", 0o755); err != nil {
		return
	}
	if err := syscall.Mount("cgroup2", "/sys/fs/cgroup", "cgroup2", syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, ""); err != nil {
		if err != syscall.EBUSY && err != syscall.ENODEV && err != syscall.ENOENT {
			fmt.Printf("[init] mount cgroup2: %v\n", err)
		}
		return
	}
	// cpuset is separate: enabling it fails when the root cgroup has no
	// cpus/mems assigned yet, and the rest must still go through.
	for _, ctrls := range []string{"+cpu +memory +pids +io", "+cpuset"} {
		if err := os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte(ctrls), 0o644); err != nil {
			fmt.Printf("[init] cgroup subtree_control %q: %v\n", ctrls, err)
		}
	}
}

func main() {
	fmt.Println()
	fmt.Println("==========================================")
	fmt.Println(" gantry guest init (PID 1, static Go)")
	fmt.Println("==========================================")

	const pseudo = syscall.MS_NOSUID | syscall.MS_NOEXEC | syscall.MS_NODEV
	// devtmpfs is usually pre-mounted by the kernel; mount the rest.
	// /dev keeps device nodes usable (no MS_NODEV) but drops suid/exec;
	// the pseudo filesystems and /tmp get the full nosuid/noexec/nodev.
	mount("devtmpfs", "/dev", "devtmpfs", syscall.MS_NOSUID|syscall.MS_NOEXEC)
	mount("proc", "/proc", "proc", pseudo)
	mount("sysfs", "/sys", "sysfs", pseudo)
	mount("tmpfs", "/tmp", "tmpfs", pseudo)
	mountCgroups()

	// Same hardening sysctls DefaultCmdline passes to production boots;
	// repeated here because this init also runs on bare debug boots whose
	// cmdline carries none of them.
	sysctl("kernel.kptr_restrict", "2")
	sysctl("kernel.dmesg_restrict", "1")
	sysctl("kernel.unprivileged_bpf_disabled", "1")
	sysctl("kernel.yama.ptrace_scope", "1")
	sysctl("kernel.kexec_load_disabled", "1")
	// Irreversible until reboot; silently skipped on our module-less
	// kernels, so this covers module-capable fallback kernels.
	sysctl("kernel.modules_disabled", "1")
	sysctl("net.core.bpf_jit_harden", "2")

	// make sure console device nodes exist even if the kernel's devtmpfs
	// population is late (PID 1 dies early without /dev/console)
	mknod("/dev/console", 5, 1)
	mknod("/dev/null", 1, 3)
	mknod("/dev/tty", 5, 0)

	var u syscall.Utsname
	if syscall.Uname(&u) == nil {
		fmt.Printf("[init] uname: %s %s %s %s\n", cstr8(u.Sysname[:]), cstr8(u.Release[:]), cstr8(u.Version[:]), cstr8(u.Machine[:]))
	}
	if motd, err := os.ReadFile("/etc/motd"); err == nil {
		fmt.Print(string(motd))
	}

	// if a virtio-blk rootfs was attached (gantry run -rootfs ...), mount
	// the real nerdbox rootfs at /mnt for exploration
	if _, err := os.Stat("/dev/vda"); err == nil {
		os.MkdirAll("/mnt", 0o755)
		if err := syscall.Mount("/dev/vda", "/mnt", "erofs", syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV, ""); err != nil {
			fmt.Printf("[init] mount /dev/vda: %v\n", err)
		} else {
			fmt.Println("[init] nerdbox rootfs mounted at /mnt (erofs, ro)")
			fmt.Println("[init] try: ls /mnt /mnt/sbin /mnt/etc")
		}
	}

	if _, err := os.Stat("/etc/rc"); err == nil {
		// non-interactive boot script (used by the QEMU smoke test)
		fmt.Println("[init] running /etc/rc")
		rc := exec.Command("/bin/busybox", "sh", "/etc/rc")
		rc.Stdin, rc.Stdout, rc.Stderr = os.Stdin, os.Stdout, os.Stderr
		rc.Env = []string{"PATH=/bin", "TERM=dumb"}
		if err := rc.Run(); err != nil {
			fmt.Printf("[init] /etc/rc: %v\n", err)
		}
	} else if _, err := os.Stat("/bin/busybox"); err == nil {
		fmt.Println("[init] starting busybox sh on /dev/console (type 'exit' to power off)")
		fmt.Println("[init] try: uname -a, cat /proc/cpuinfo, ls /, ip addr (no net device in gantry v1)")
		sh := exec.Command("/bin/busybox", "sh")
		sh.Stdin, sh.Stdout, sh.Stderr = os.Stdin, os.Stdout, os.Stderr
		sh.Env = []string{"PATH=/bin", "HOME=/root", "TERM=dumb", "PS1=guest# "}
		if err := sh.Run(); err != nil {
			fmt.Printf("[init] shell: %v\n", err)
		}
	} else {
		fmt.Println("[init] no /bin/busybox; idling 5s")
		time.Sleep(5 * time.Second)
	}

	fmt.Println("[init] powering off via PSCI SYSTEM_OFF")
	syscall.Sync()
	poweroff()
}

func mknod(path string, major, minor uint32) {
	dev := int(major<<8 | minor)
	if err := syscall.Mknod(path, syscall.S_IFCHR|0o600, dev); err != nil {
		fmt.Printf("[init] mknod %s: %v\n", path, err)
	}
}

func poweroff() {
	const (
		sysReboot         = 142 // aarch64
		rebootMagic1      = 0xfee1dead
		rebootMagic2      = 672274793
		rebootCmdPowerOff = 0x4321fedc
	)
	_, _, errno := syscall.Syscall(sysReboot, rebootMagic1, rebootMagic2, rebootCmdPowerOff)
	// If poweroff failed, exiting as PID 1 still ends the VM: the kernel
	// panics ("Attempted to kill init") and panic=-1 triggers a PSCI reset.
	// (Never block here — a PID-1 deadlock is a Go fatal error.)
	fmt.Printf("[init] reboot syscall: %v; exiting to trigger PSCI reset\n", errno)
	os.Exit(0)
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func cstr8(b []int8) string {
	s := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		s = append(s, byte(c))
	}
	return string(s)
}
