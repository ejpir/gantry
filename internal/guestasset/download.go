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
	"github.com/ejpir/gantry/internal/sandbox/localsec"
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

// EnsureImage is EnsureKernel for Gantry's default release OCI image.
func EnsureImage(path string, progress func(string, ...any)) (string, error) {
	return ensure(path, imageAsset, progress)
}

// EnsureGuestTools is EnsureKernel for the multicall guest helper binary.
func EnsureGuestTools(path string, progress func(string, ...any)) (string, error) {
	return ensure(path, guestToolsAsset, progress)
}

type assetKind string

const (
	kernelAsset     assetKind = "kernel"
	rootfsAsset     assetKind = "rootfs"
	imageAsset      assetKind = "image"
	guestToolsAsset assetKind = "guest-tools"
)

func ensure(path string, kind assetKind, progress func(string, ...any)) (string, error) {
	if root, ok := fallbackAssetRoot(path); ok {
		if err := localsec.CreateManagerDir(root); err != nil {
			return "", fmt.Errorf("secure temporary asset cache %s: %w", root, err)
		}
	}
	if info, err := os.Lstat(path); err == nil {
		if err := localsec.SecureRegularFile(path); err != nil {
			return "", fmt.Errorf("validate existing %s %s: %w", kind, path, err)
		}
		if info.Size() <= 0 || info.Size() > maxAssetSize {
			return "", fmt.Errorf("validate existing %s %s: size %d is outside 1..%d bytes", kind, path, info.Size(), maxAssetSize)
		}
		return path, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("inspect %s %s: %w", kind, path, err)
	}
	if !downloadable(filepath.Base(path), kind) {
		return "", fmt.Errorf("%s %s not found", kind, path)
	}
	if err := download(path, progress); err != nil {
		return "", err
	}
	if err := localsec.SecureRegularFile(path); err != nil {
		return "", fmt.Errorf("secure downloaded %s %s: %w", kind, path, err)
	}
	return path, nil
}

func fallbackAssetRoot(path string) (string, bool) {
	temp := filepath.Clean(systemTempDir())
	root := filepath.Join(temp, fallbackAssetDirName())
	rel, err := filepath.Rel(root, filepath.Clean(path))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return root, true
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
	case imageAsset:
		return name == "gantry-default-image-arm64.erofs" ||
			name == "gantry-default-image-x86_64.erofs"
	case guestToolsAsset:
		return name == "gantry-guest-arm64" ||
			name == "gantry-guest-x86_64"
	default:
		return false
	}
}

func releaseBase() string {
	if base := os.Getenv("GANTRY_RELEASE_BASE"); base != "" {
		return strings.TrimRight(base, "/")
	}
	if releaseVersionRE.MatchString(Version) {
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
	assetDir := filepath.Dir(dest)
	if err := os.MkdirAll(assetDir, 0o700); err != nil {
		return fmt.Errorf("create user asset directory %s: %w", assetDir, err)
	}

	if err := atomicfile.WriteDurable(dest, 0o644, func(writer io.Writer) error {
		body := io.Reader(resp.Body)
		var tracked *assetProgressReader
		if progress != nil {
			tracked = &assetProgressReader{
				reader: resp.Body, name: filepath.Base(dest), total: resp.ContentLength,
				progress: progress,
			}
			body = tracked
		}
		err := copyVerified(writer, body, wantSum, maxAssetSize)
		if err == nil && tracked != nil {
			tracked.finish()
		}
		return err
	}); err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	if progress != nil {
		progress("staged %s", dest)
	}
	return nil
}

type assetProgressReader struct {
	reader     io.Reader
	name       string
	total      int64
	read       int64
	lastReport time.Time
	progress   func(string, ...any)
	complete   bool
}

func (r *assetProgressReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += int64(n)
	now := time.Now()
	complete := r.total > 0 && r.read >= r.total
	if n > 0 && (r.lastReport.IsZero() || complete || now.Sub(r.lastReport) >= 100*time.Millisecond) {
		r.lastReport = now
		r.progress("%s", formatAssetProgress(r.name, r.read, r.total))
		r.complete = complete
	}
	return n, err
}

func (r *assetProgressReader) finish() {
	if r.complete {
		return
	}
	total := r.total
	if total <= 0 {
		total = r.read
	}
	r.progress("%s", formatAssetProgress(r.name, r.read, total))
	r.complete = true
}

func formatAssetProgress(name string, received, total int64) string {
	if total <= 0 {
		return fmt.Sprintf("downloading %s [····················] %s", name, formatByteCount(received))
	}
	percent := int(received * 100 / total)
	if percent > 100 {
		percent = 100
	}
	filled := percent * 20 / 100
	bar := strings.Repeat("=", filled) + strings.Repeat("·", 20-filled)
	return fmt.Sprintf("downloading %s [%s] %3d%% (%s/%s)",
		name, bar, percent, formatByteCount(received), formatByteCount(total))
}

func formatByteCount(bytes int64) string {
	const mebibyte = int64(1 << 20)
	if bytes < mebibyte {
		return fmt.Sprintf("%.1f KiB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.1f MiB", float64(bytes)/float64(mebibyte))
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
