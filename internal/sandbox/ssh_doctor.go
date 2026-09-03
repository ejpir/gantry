package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func cmdSSHDoctor(name string) int {
	name = strings.TrimSuffix(name, ".gantry")
	if err := layout.ValidateName(name); err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh doctor:", err)
		return 2
	}
	cfg, err := readSSHConfig(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh doctor:", err)
		return 1
	}
	fmt.Printf("%-18s %s\n", "SSH enabled", yesNo(cfg.SSH))
	fmt.Printf("%-18s %s\n", "Dev Containers", yesNo(cfg.DevContainers))
	if _, alive := layout.PID(name); !alive {
		fmt.Printf("%-18s no\nRemote-SSH will fail: sandbox is stopped (run gantry resume %s)\n", "Sandbox running", name)
		return 1
	}
	fmt.Printf("%-18s yes\n", "Sandbox running")
	if !cfg.SSH {
		fmt.Printf("Remote-SSH will fail: SSH is disabled (run gantry configure %s -ssh)\n", name)
		return 1
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Println("Remote-SSH will fail: cannot locate the Gantry executable")
		return 1
	}
	const probe = `
check() { if "$@" >/dev/null 2>&1; then echo yes; else echo no; fi; }
echo GANTRY_SSH_DOCTOR_sh=yes
echo GANTRY_SSH_DOCTOR_tar=$(check command -v tar)
if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then d=yes; else d=no; fi
echo GANTRY_SSH_DOCTOR_downloader=$d
if getconf GNU_LIBC_VERSION >/dev/null 2>&1; then l=yes; elif ls /lib/ld-musl-*.so.1 >/dev/null 2>&1 && ls /usr/lib/libstdc++.so* >/dev/null 2>&1; then l=yes; else l=no; fi
echo GANTRY_SSH_DOCTOR_runtime=$l
if [ -n "$HOME" ] && [ -d "$HOME" ] && [ -w "$HOME" ]; then h=yes; else h=no; fi
echo GANTRY_SSH_DOCTOR_home=$h
echo GANTRY_SSH_DOCTOR_user=$(id -un 2>/dev/null || echo unknown)
echo GANTRY_SSH_DOCTOR_podman=$(check command -v podman)
echo GANTRY_SSH_DOCTOR_fuse=$(check test -c /dev/fuse)
echo GANTRY_SSH_DOCTOR_tun=$(check test -c /dev/net/tun)
`
	// Probe the environment the SSH gateway actually selects. With Dev
	// Containers enabled this is the curated IDE peer container, while ordinary
	// `gantry exec` deliberately remains in the workload image.
	output, probeErr := exec.Command(self, "ssh", name, "--", "sh", "-c", probe).CombinedOutput()
	values := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok && strings.HasPrefix(key, "GANTRY_SSH_DOCTOR_") {
			values[strings.TrimPrefix(key, "GANTRY_SSH_DOCTOR_")] = value
		}
	}
	if probeErr != nil || values["sh"] != "yes" {
		fmt.Printf("%-18s no\n", "Bourne shell")
		fmt.Println("Remote-SSH will fail: no sh in image (install one or choose another image)")
		return 1
	}
	fmt.Printf("%-18s %s\n", "Bourne shell", values["sh"])
	fmt.Printf("%-18s %s\n", "tar", values["tar"])
	fmt.Printf("%-18s %s\n", "curl or wget", values["downloader"])
	fmt.Printf("%-18s %s\n", "libc + libstdc++", values["runtime"])
	fmt.Printf("%-18s %s\n", "Writable HOME", values["home"])
	fmt.Printf("%-18s %s\n", "Default user", values["user"])
	for _, requirement := range []struct{ key, fix string }{
		{"tar", "no tar in image"},
		{"runtime", "editor runtime requirements are missing"},
		{"home", "default user's HOME is not writable"},
	} {
		if values[requirement.key] != "yes" {
			fmt.Printf("Remote-SSH will fail: %s (fix the image)\n", requirement.fix)
			return 1
		}
	}
	if cfg.DevContainers {
		fmt.Printf("%-18s %s\n", "Podman", values["podman"])
		fmt.Printf("%-18s %s\n", "/dev/fuse", values["fuse"])
		fmt.Printf("%-18s %s\n", "/dev/net/tun", values["tun"])
		if values["podman"] != "yes" || values["fuse"] != "yes" || values["tun"] != "yes" {
			fmt.Println("Dev Containers will fail: curated IDE image or nested-runtime devices are incomplete")
			return 1
		}
	}
	if values["downloader"] != "yes" {
		fmt.Println("Remote-SSH ready for client-side server upload; set remote.SSH.localServerDownload=always")
		return 0
	}
	fmt.Println("Remote-SSH ready")
	return 0
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
