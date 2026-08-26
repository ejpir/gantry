// Package guestasset locates and stages the host-side artifacts used to boot
// guests. It deliberately has no dependency on the VMM: release, cache, and
// filesystem policy belong to the supervisor side of the process boundary.
package guestasset

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/ejpir/gantry/internal/gutil"
)

var (
	userCacheDir        = os.UserCacheDir
	userHomeDir         = os.UserHomeDir
	systemTempDir       = os.TempDir
	currentUserIdentity = func() string {
		if current, err := user.Current(); err == nil {
			return current.Uid + "\x00" + current.Username
		}
		// A process-specific fallback sacrifices cache reuse rather than
		// sharing a predictable directory with another account.
		return strings.Join([]string{os.Getenv("USER"), os.Getenv("USERNAME"), strconv.Itoa(os.Getpid())}, "\x00")
	}
)

var (
	releaseVersionRE = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?$`)
	releaseBuildIDRE = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)
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

// releaseAssetPath returns a cache destination isolated by the release tag.
// Replacing a release binary must never reuse a same-named kernel from an
// older release. os.UserCacheDir maps to LocalAppData on Windows, so staging
// release assets neither depends on the current directory nor needs elevation.
//
// GANTRY_ARTIFACTS remains an explicit staging override for development,
// packaging, and air-gapped installations. Development binaries retain the
// source-tree/cwd lookup performed by Path because "dev" does not identify an
// immutable release.
func releaseAssetPath(name string) string {
	if dir := os.Getenv("GANTRY_ARTIFACTS"); dir != "" {
		return filepath.Join(dir, name)
	}
	if !releaseVersionRE.MatchString(Version) {
		return Path(name)
	}
	if cache, err := userCacheDir(); err == nil && cache != "" {
		return filepath.Join(cache, "gantry", "assets", releaseAssetCacheKey(), name)
	}
	// UserCacheDir should be available on every supported host. Keep a
	// user-writable fallback for unusual stripped-down environments instead of
	// falling back to the process cwd (which may be Program Files on Windows).
	if home, err := userHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".gantry", "assets", releaseAssetCacheKey(), name)
	}
	// The OS temp directory is the final user-writable fallback. Isolate its
	// otherwise shared namespace by account; ensure() verifies and hardens this
	// root before trusting any existing artifact beneath it.
	return filepath.Join(systemTempDir(), fallbackAssetDirName(), "assets", releaseAssetCacheKey(), name)
}

func releaseAssetCacheKey() string {
	if !releaseBuildIDRE.MatchString(BuildID) {
		return Version
	}
	return Version + "-" + strings.ToLower(BuildID)
}

func fallbackAssetDirName() string {
	sum := sha256.Sum256([]byte(currentUserIdentity()))
	return "gantry-" + hex.EncodeToString(sum[:6])
}

// DefaultKernel always selects Gantry's owned kernel. A stock nerdbox kernel
// remains available only through an explicit -kernel path (and KernelChoices
// for interactive selection); it is never a silent unattended fallback.
func DefaultKernel() string {
	gantry, _ := kernelNames(runtime.GOARCH)
	return releaseAssetPath(gantry)
}

// IsManagedReleaseKernel reports whether path has the layout used by a
// versioned Gantry release cache. It is intentionally strict: callers use it
// only to migrate sandbox configs written before kernel provenance was
// persisted, so an ambiguous/custom path must remain pinned.
func IsManagedReleaseKernel(path string) bool {
	if !downloadable(filepath.Base(path), kernelAsset) {
		return false
	}
	versionDir := filepath.Dir(filepath.Clean(path))
	versionName := filepath.Base(versionDir)
	if split := strings.LastIndex(versionName, "-"); split > 0 &&
		releaseVersionRE.MatchString(versionName[:split]) && releaseBuildIDRE.MatchString(versionName[split+1:]) {
		versionName = versionName[:split]
	}
	if !releaseVersionRE.MatchString(versionName) {
		return false
	}
	assetsDir := filepath.Dir(versionDir)
	return filepath.Base(assetsDir) == "assets" && filepath.Base(filepath.Dir(assetsDir)) == "gantry"
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

// DefaultGuestTools returns the release's multicall guest helper binary
// (gantry-guest) for the host architecture. The daemon stages it into
// guests that configure host-bound secrets.
func DefaultGuestTools() string {
	if runtime.GOARCH == "amd64" {
		return releaseAssetPath("gantry-guest-x86_64")
	}
	return releaseAssetPath("gantry-guest-arm64")
}

// DefaultRootfs returns the release rootfs for the host architecture.
func DefaultRootfs() string {
	if runtime.GOARCH == "amd64" {
		return releaseAssetPath("nerdbox-rootfs-x86_64.erofs")
	}
	return releaseAssetPath("nerdbox-rootfs-arm64.erofs")
}

// DefaultImage returns the release's small Alpine OCI image for tagged
// binaries. Development builds retain the source-tree convention: prefer a
// staged Debian image and then the locally generated shell image.
func DefaultImage() string {
	if releaseVersionRE.MatchString(Version) {
		name := "gantry-default-image-arm64.erofs"
		if runtime.GOARCH == "amd64" {
			name = "gantry-default-image-x86_64.erofs"
		}
		return releaseAssetPath(name)
	}
	if path := Path("debian-bookworm.erofs"); gutil.FileExists(path) {
		return path
	}
	return Path("shell-rootfs.erofs")
}

// DefaultDevContainersImage returns the curated glibc development image.
// Unlike the workload default it is intentionally uniform: editor
// prerequisites, the OS-managed CA store and Podman/Buildah tooling with an
// unprivileged gantry user. Nested-runtime authority remains explicitly gated.
func DefaultDevContainersImage() string {
	name := "gantry-ide-image-arm64.erofs"
	if runtime.GOARCH == "amd64" {
		name = "gantry-ide-image-x86_64.erofs"
	}
	return releaseAssetPath(name)
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
