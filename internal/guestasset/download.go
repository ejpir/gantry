package guestasset

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/gutil"
)

// Version is the Gantry release tag stamped by release builds. Development
// builds use the latest release so locally built supervisors can bootstrap
// without a matching tag.
var Version = "dev"

const (
	maxAssetSize    = int64(256 << 20)
	maxChecksumSize = int64(4 << 10)
)

// EnsureKernel returns path when it already exists. A missing Gantry release
// kernel is downloaded, verified, and atomically staged at path.
func EnsureKernel(path string, progress func(string, ...any)) (string, error) {
	return ensure(path, kernelAsset, progress)
}

// EnsureRootfs is EnsureKernel for a supported release rootfs.
func EnsureRootfs(path string, progress func(string, ...any)) (string, error) {
	return ensure(path, rootfsAsset, progress)
}

type assetKind string

const (
	kernelAsset assetKind = "kernel"
	rootfsAsset assetKind = "rootfs"
)

func ensure(path string, kind assetKind, progress func(string, ...any)) (string, error) {
	if gutil.FileExists(path) {
		return path, nil
	}
	if !downloadable(filepath.Base(path), kind) {
		return "", fmt.Errorf("%s %s not found", kind, path)
	}
	if err := download(path, progress); err != nil {
		return "", err
	}
	return path, nil
}

func downloadable(name string, kind assetKind) bool {
	switch kind {
	case kernelAsset:
		return name == "gantry-kernel-arm64" ||
			name == "gantry-kernel-arm64-4k" ||
			name == "gantry-kernel-x86_64"
	case rootfsAsset:
		return name == "nerdbox-rootfs-arm64.erofs" ||
			name == "nerdbox-rootfs-x86_64.erofs" ||
			name == "nerdbox-rootfs-gvisor-arm64.erofs" ||
			name == "nerdbox-rootfs-gvisor-x86_64.erofs"
	default:
		return false
	}
}

func releaseBase() string {
	if base := os.Getenv("GANTRY_RELEASE_BASE"); base != "" {
		return strings.TrimRight(base, "/")
	}
	if strings.HasPrefix(Version, "v") {
		return "https://github.com/ejpir/gantry/releases/download/" + Version
	}
	return "https://github.com/ejpir/gantry/releases/latest/download"
}

func download(dest string, progress func(string, ...any)) error {
	base := releaseBase()
	url := base + "/" + filepath.Base(dest)
	if progress != nil {
		progress("downloading %s from %s (first start only)", filepath.Base(dest), base)
	}

	wantSum, err := fetchSHA256(url + ".sha256")
	if err != nil {
		return fmt.Errorf("integrity file %s.sha256: %w", url, err)
	}
	client := &http.Client{Timeout: 15 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", url, resp.Status)
	}
	if resp.ContentLength > maxAssetSize {
		return fmt.Errorf("download %s: asset exceeds %d bytes", url, maxAssetSize)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}

	if err := atomicfile.WriteDurable(dest, 0o644, func(writer io.Writer) error {
		return copyVerified(writer, resp.Body, wantSum, maxAssetSize)
	}); err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	if progress != nil {
		progress("staged %s", dest)
	}
	return nil
}

func copyVerified(dst io.Writer, src io.Reader, wantSum string, limit int64) error {
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, hash), io.LimitReader(src, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("asset exceeds %d bytes", limit)
	}
	if gotSum := hex.EncodeToString(hash.Sum(nil)); gotSum != wantSum {
		return fmt.Errorf("sha256 mismatch (got %s, want %s)", gotSum, wantSum)
	}
	return nil
}

func fetchSHA256(url string) (string, error) {
	client := &http.Client{Timeout: time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s (refusing unverified download)", resp.Status)
	}
	if resp.ContentLength > maxChecksumSize {
		return "", fmt.Errorf("sha256 sidecar exceeds %d bytes", maxChecksumSize)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChecksumSize+1))
	if err != nil {
		return "", err
	}
	if int64(len(body)) > maxChecksumSize {
		return "", fmt.Errorf("sha256 sidecar exceeds %d bytes", maxChecksumSize)
	}
	fields := strings.Fields(string(body))
	if len(fields) == 0 || len(fields[0]) != 64 {
		return "", fmt.Errorf("malformed sha256 sidecar")
	}
	sum := strings.ToLower(fields[0])
	if _, err := hex.DecodeString(sum); err != nil {
		return "", fmt.Errorf("malformed sha256 sidecar")
	}
	return sum, nil
}
