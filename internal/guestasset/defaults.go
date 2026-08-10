// Package guestasset locates and stages the host-side artifacts used to boot
// guests. It deliberately has no dependency on the VMM: release, cache, and
// filesystem policy belong to the supervisor side of the process boundary.
package guestasset

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ejpir/gantry/internal/gutil"
)

// Path returns the conventional location of a generated guest artifact.
// GANTRY_ARTIFACTS selects an explicit artifact directory. In a source
// checkout, artifacts/ is preferred when the named file has been staged
// there; the working-directory path remains the fallback used by existing
// development workflows.
func Path(name string) string {
	if dir := os.Getenv("GANTRY_ARTIFACTS"); dir != "" {
		return filepath.Join(dir, name)
	}
	if candidate := filepath.Join("artifacts", name); gutil.FileExists(candidate) {
		return candidate
	}
	return name
}

// DefaultKernel selects Gantry's hardened kernel when it is staged, then the
// stock nerdbox kernel. When neither exists, it returns the hardened kernel's
// destination so EnsureKernel can stage it on demand.
func DefaultKernel() string {
	gantry, nerdbox := kernelNames(runtime.GOARCH)
	if path := Path(gantry); gutil.FileExists(path) {
		return path
	}
	if path := Path(nerdbox); gutil.FileExists(path) {
		return path
	}
	return Path(gantry)
}

// KernelChoices returns staged kernels for the host architecture in artifact
// search order. It does no downloading and is intended for explicit user
// selection; callers should use DefaultKernel for unattended boot.
func KernelChoices() []string {
	gantry, nerdbox := kernelNames(runtime.GOARCH)
	dirs := []string{"."}
	if dir := os.Getenv("GANTRY_ARTIFACTS"); dir != "" {
		dirs = append([]string{dir}, dirs...)
	} else {
		dirs = append([]string{"artifacts"}, dirs...)
	}

	seen := make(map[string]struct{})
	var choices []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || (!strings.HasPrefix(name, gantry) && !strings.HasPrefix(name, nerdbox)) {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			choices = append(choices, filepath.Join(dir, name))
		}
	}
	return choices
}

func kernelNames(goarch string) (gantry, nerdbox string) {
	if goarch == "amd64" {
		return "gantry-kernel-x86_64", "nerdbox-kernel-x86_64"
	}
	return "gantry-kernel-arm64", "nerdbox-kernel-arm64"
}

// DefaultRootfs returns the release rootfs for the host architecture.
func DefaultRootfs() string {
	if runtime.GOARCH == "amd64" {
		return Path("nerdbox-rootfs-x86_64.erofs")
	}
	return Path("nerdbox-rootfs-arm64.erofs")
}

// DefaultImage selects the full Debian image when staged, otherwise the small
// debug image. Both are generated artifacts rather than source files.
func DefaultImage() string {
	if path := Path("debian-bookworm.erofs"); gutil.FileExists(path) {
		return path
	}
	return Path("shell-rootfs.erofs")
}

// GVisorRootfs maps a rootfs image name to its gVisor variant.
func GVisorRootfs(path string) string {
	if strings.Contains(path, "rootfs-gvisor-") {
		return path
	}
	return strings.Replace(path, "rootfs-", "rootfs-gvisor-", 1)
}

// GVisorKernel maps an arm64 kernel name to its 4 KiB-page variant. Stock
// nerdbox arm64 kernels use 16 KiB pages, which stock runsc cannot boot.
// x86-64 kernels already use 4 KiB pages.
func GVisorKernel(path string) string {
	if runtime.GOARCH != "arm64" || strings.HasSuffix(path, "-4k") {
		return path
	}
	return path + "-4k"
}
