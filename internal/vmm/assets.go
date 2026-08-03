package vmm

// On-demand guest-asset downloads: the CLI ships without guest kernels or
// rootfs images and fetches gantry-kernel-<arch>[-4k] and
// nerdbox-rootfs-<arch>.erofs from the GitHub release page the first time a
// sandbox needs them. Downloads go to the artifacts dir next to the other
// staged assets and are atomic (temp file + rename), so a killed download
// never leaves a half-written asset behind.

import (
	"fmt"
	"gantry/internal/gutil"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// releaseBase is the stable "latest release" download prefix. Releases are
// tagged v*; the CI attaches gantry-kernel-<arch>[-4k] and
// nerdbox-rootfs-<arch>.erofs assets to them. GANTRY_RELEASE_BASE overrides
// the prefix for mirrors and tests.
const defaultReleaseBase = "https://github.com/ejpir/gantry/releases/latest/download"

func releaseBase() string {
	if b := os.Getenv("GANTRY_RELEASE_BASE"); b != "" {
		return strings.TrimRight(b, "/")
	}
	return defaultReleaseBase
}

// downloadableAsset reports whether path names a guest asset Gantry can
// fetch itself (as opposed to a user-supplied path or a locally built
// variant such as the gVisor rootfs, which we do not distribute).
func downloadableAsset(path string) bool {
	base := filepath.Base(path)
	if strings.HasPrefix(base, "gantry-kernel-") {
		return true
	}
	switch base {
	case "nerdbox-rootfs-arm64.erofs", "nerdbox-rootfs-x86_64.erofs":
		return true
	}
	return false
}

// EnsureKernel returns path if it exists; otherwise, when path names a
// gantry-kernel-* asset, downloads it from the release page into place and
// returns the same path. progress (may be nil) reports the download start
// so users understand the first-start delay.
func EnsureKernel(path string, progress func(string, ...any)) (string, error) {
	return ensureAsset(path, "kernel", progress)
}

// EnsureRootfs is EnsureKernel for the nerdbox-rootfs-<arch>.erofs guest
// rootfs asset.
func EnsureRootfs(path string, progress func(string, ...any)) (string, error) {
	return ensureAsset(path, "rootfs", progress)
}

func ensureAsset(path, what string, progress func(string, ...any)) (string, error) {
	if gutil.FileExists(path) {
		return path, nil
	}
	if !downloadableAsset(path) {
		return "", fmt.Errorf("%s %s not found", what, path)
	}
	if err := downloadAsset(path, progress); err != nil {
		return "", err
	}
	return path, nil
}

func downloadAsset(dest string, progress func(string, ...any)) error {
	url := releaseBase() + "/" + filepath.Base(dest)
	if progress != nil {
		progress("downloading %s from %s (first start only)", filepath.Base(dest), releaseBase())
	}
	client := &http.Client{Timeout: 15 * time.Minute}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", url, resp.Status)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".gantry-download-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	// Kernels are ~15-20 MB; cap well above that to catch truncated or
	// wildly wrong responses (e.g. an HTML error page behind a proxy).
	const maxAsset = 256 << 20
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, maxAsset)); err != nil {
		tmp.Close()
		return fmt.Errorf("download %s: %w", url, err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return err
	}
	if progress != nil {
		progress("staged %s", dest)
	}
	return nil
}
