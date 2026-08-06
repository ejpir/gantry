package vmm

// On-demand guest-asset downloads: the CLI ships without guest kernels or
// rootfs images and fetches gantry-kernel-<arch>[-4k] and
// nerdbox-rootfs[-gvisor]-<arch>.erofs from the GitHub release page the
// first time a sandbox needs them. Downloads go to the artifacts dir next
// to the other staged assets and are atomic (temp file + rename), so a
// killed download never leaves a half-written asset behind.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"gantry/internal/gutil"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Version is the gantry release tag (e.g. "v0.0.2") stamped by the CI via
// -ldflags; dev builds keep "dev". Released binaries download guest assets
// from their own release (version binding), dev builds from latest.
var Version = "dev"

// releaseBase is the download prefix for guest assets. Releases are tagged
// v*; the CI attaches gantry-kernel-<arch>[-4k] and
// nerdbox-rootfs[-gvisor]-<arch>.erofs assets plus a <asset>.sha256 sidecar
// to them. GANTRY_RELEASE_BASE overrides the prefix for mirrors and tests.
func releaseBase() string {
	if b := os.Getenv("GANTRY_RELEASE_BASE"); b != "" {
		return strings.TrimRight(b, "/")
	}
	if strings.HasPrefix(Version, "v") {
		return "https://github.com/ejpir/gantry/releases/download/" + Version
	}
	return "https://github.com/ejpir/gantry/releases/latest/download"
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
	case "nerdbox-rootfs-arm64.erofs", "nerdbox-rootfs-x86_64.erofs",
		// The gVisor variant runsc maps to is a first-class release asset
		// too (built by the guest-assets CI job via mkrootfs-gvisor.sh).
		"nerdbox-rootfs-gvisor-arm64.erofs", "nerdbox-rootfs-gvisor-x86_64.erofs":
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
	base := releaseBase()
	url := base + "/" + filepath.Base(dest)
	if progress != nil {
		progress("downloading %s from %s (first start only)", filepath.Base(dest), base)
	}
	// The integrity sidecar is published next to the asset by the release
	// job; without it there is nothing trustworthy to verify against, so
	// fail closed.
	wantSum, err := fetchSHA256(url + ".sha256")
	if err != nil {
		return fmt.Errorf("integrity file %s.sha256: %w", url, err)
	}
	client := &http.Client{Timeout: 15 * time.Minute}
	resp, err := client.Get(url)
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
	// Read one byte past the cap so an oversized response is an error
	// instead of a silently cached truncation.
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxAssetSize+1))
	if err != nil {
		tmp.Close()
		return fmt.Errorf("download %s: %w", url, err)
	}
	if n > maxAssetSize {
		tmp.Close()
		return fmt.Errorf("download %s: asset exceeds %d bytes", url, maxAssetSize)
	}
	if gotSum := hex.EncodeToString(h.Sum(nil)); gotSum != wantSum {
		tmp.Close()
		return fmt.Errorf("download %s: sha256 mismatch (got %s, want %s)", url, gotSum, wantSum)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
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

// maxAssetSize caps one guest asset download. A var so tests can shrink it.
var maxAssetSize = int64(256 << 20)

// fetchSHA256 downloads a <asset>.sha256 sidecar ("<hex>  <name>") and
// returns the hex digest.
func fetchSHA256(url string) (string, error) {
	client := &http.Client{Timeout: time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s (refusing unverified download)", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", err
	}
	sum := strings.Fields(string(body))
	if len(sum) == 0 || len(sum[0]) != 64 {
		return "", fmt.Errorf("malformed sha256 sidecar")
	}
	return strings.ToLower(sum[0]), nil
}
