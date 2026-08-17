// Package selfupdate discovers Gantry releases and installs a verified
// platform binary over the currently running executable.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/guestasset"
	"golang.org/x/mod/semver"
)

const (
	checkInterval      = 24 * time.Hour
	failedCheckRetry   = time.Hour
	maxReleaseMetadata = int64(64 << 10)
	maxChecksumSize    = int64(4 << 10)
	maxBinarySize      = int64(256 << 20)
)

var (
	latestReleaseEndpoint = "https://api.github.com/repos/ejpir/gantry/releases/latest"
	releaseDownloadBase   = "https://github.com/ejpir/gantry/releases/download"
	httpClient            = &http.Client{Timeout: 15 * time.Minute}
	now                   = time.Now
	cacheFile             = defaultCacheFile
	executablePath        = currentExecutablePath
)

// Status describes the relationship between this binary and GitHub's latest
// stable release. Development binaries deliberately do not participate.
type Status struct {
	Current   string
	Latest    string
	Available bool
}

// Result describes an installed update. Replacement always completes before
// Apply returns; every platform can rename an executable that is running.
type Result struct {
	Previous   string
	Installed  string
	Executable string
}

type cacheEntry struct {
	CheckedAt time.Time `json:"checkedAt"`
	Latest    string    `json:"latest,omitempty"`
	Failed    bool      `json:"failed,omitempty"`
}

type releaseResponse struct {
	TagName string `json:"tag_name"`
}

// Current returns the release tag stamped into this binary.
func Current() string { return guestasset.Version }

// Enabled reports whether the binary has a comparable release version.
func Enabled() bool { return semver.IsValid(Current()) }

// Check asks GitHub for the latest stable release. It performs no I/O for a
// development build because "dev" cannot be ordered against release tags.
func Check(ctx context.Context) (Status, error) {
	status := Status{Current: Current()}
	if !semver.IsValid(status.Current) {
		return status, nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, latestReleaseEndpoint, nil)
	if err != nil {
		return status, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "gantry/"+status.Current)
	response, err := httpClient.Do(request)
	if err != nil {
		return status, fmt.Errorf("check latest release: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxReleaseMetadata))
		return status, fmt.Errorf("check latest release: %s", response.Status)
	}
	var release releaseResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxReleaseMetadata+1))
	if err := decoder.Decode(&release); err != nil {
		return status, fmt.Errorf("decode latest release: %w", err)
	}
	if !semver.IsValid(release.TagName) {
		return status, fmt.Errorf("latest release returned invalid tag %q", release.TagName)
	}
	status.Latest = release.TagName
	status.Available = semver.Compare(status.Latest, status.Current) > 0
	return status, nil
}

// Refresh checks the network and records derived status for later CLI runs.
func Refresh(ctx context.Context) (Status, error) {
	status, err := Check(ctx)
	if !Enabled() {
		return status, err
	}
	entry := cacheEntry{CheckedAt: now(), Latest: status.Latest, Failed: err != nil}
	if cacheErr := writeCache(entry); cacheErr != nil {
		if err != nil {
			return status, errors.Join(err, cacheErr)
		}
		return status, cacheErr
	}
	return status, err
}

// Cached returns the last discovered status and whether another background
// refresh is due. A stale positive result remains useful until refreshed.
func Cached() (status Status, found, fresh bool) {
	status.Current = Current()
	if !Enabled() {
		return status, false, true
	}
	data, err := os.ReadFile(cacheFile())
	if err != nil {
		return status, false, false
	}
	var entry cacheEntry
	if json.Unmarshal(data, &entry) != nil || entry.CheckedAt.IsZero() {
		return status, false, false
	}
	found = true
	status.Latest = entry.Latest
	status.Available = semver.IsValid(status.Latest) && semver.Compare(status.Latest, status.Current) > 0
	interval := checkInterval
	if entry.Failed {
		interval = failedCheckRetry
	}
	fresh = now().Sub(entry.CheckedAt) >= 0 && now().Sub(entry.CheckedAt) < interval
	return status, found, fresh
}

func writeCache(entry cacheEntry) error {
	path := cacheFile()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create update cache: %w", err)
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if err := atomicfile.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write update cache: %w", err)
	}
	return nil
}

func defaultCacheFile() string {
	if dir, err := os.UserCacheDir(); err == nil && dir != "" {
		return filepath.Join(dir, "gantry", "update-check.json")
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "gantry", "update-check.json")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("gantry-%d", os.Getuid()), "update-check.json")
}

// Apply downloads the latest platform binary and its checksum sidecar, then
// replaces the current executable atomically or stages a post-exit handoff.
func Apply(ctx context.Context, progress func(string, ...any)) (Result, error) {
	status, err := Refresh(ctx)
	if err != nil {
		return Result{}, err
	}
	if !semver.IsValid(status.Current) {
		return Result{}, fmt.Errorf("development builds cannot self-update; install a tagged Gantry release first")
	}
	if !status.Available {
		return Result{Previous: status.Current, Installed: status.Current}, nil
	}
	target, err := executablePath()
	if err != nil {
		return Result{}, err
	}
	staged, err := stageBinary(ctx, target, status.Latest, progress)
	if err != nil {
		return Result{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(staged)
		}
	}()
	if err := installStaged(staged, target); err != nil {
		return Result{}, err
	}
	committed = true
	return Result{
		Previous: status.Current, Installed: status.Latest, Executable: target,
	}, nil
}

func currentExecutablePath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate Gantry executable: %w", err)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve Gantry executable: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(path); resolveErr == nil {
		path = resolved
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("inspect Gantry executable %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("gantry executable %s is not a regular file", path)
	}
	return path, nil
}

func stageBinary(ctx context.Context, target, version string, progress func(string, ...any)) (staged string, retErr error) {
	asset, err := platformAsset(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return "", err
	}
	base := strings.TrimRight(releaseDownloadBase, "/") + "/" + version + "/" + asset
	want, err := fetchChecksum(ctx, base+".sha256")
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", "gantry/"+Current())
	response, err := httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", asset, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: %s", asset, response.Status)
	}
	if response.ContentLength > maxBinarySize {
		return "", fmt.Errorf("download %s: binary exceeds %d bytes", asset, maxBinarySize)
	}
	info, err := os.Stat(target)
	if err != nil {
		return "", fmt.Errorf("inspect Gantry executable: %w", err)
	}
	mode := info.Mode().Perm()
	if mode&0o111 == 0 {
		mode |= 0o111
	}
	file, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".update-*")
	if err != nil {
		return "", fmt.Errorf("stage update beside %s: %w", target, err)
	}
	staged = file.Name()
	defer func() {
		if retErr != nil {
			_ = file.Close()
			_ = os.Remove(staged)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return "", fmt.Errorf("set staged executable permissions: %w", err)
	}
	hash := sha256.New()
	reader := io.Reader(response.Body)
	var tracked *progressReader
	if progress != nil {
		tracked = &progressReader{reader: response.Body, name: asset, total: response.ContentLength, report: progress}
		reader = tracked
	}
	n, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(reader, maxBinarySize+1))
	if err != nil {
		return "", fmt.Errorf("download %s: %w", asset, err)
	}
	if n > maxBinarySize {
		return "", fmt.Errorf("download %s: binary exceeds %d bytes", asset, maxBinarySize)
	}
	if tracked != nil {
		tracked.finish()
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != want {
		return "", fmt.Errorf("verify %s: sha256 mismatch (got %s, want %s)", asset, got, want)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync staged update: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close staged update: %w", err)
	}
	if err := validateBinary(staged, runtime.GOOS, runtime.GOARCH); err != nil {
		return "", fmt.Errorf("verify %s: %w", asset, err)
	}
	if err := validatePlatformSignature(staged); err != nil {
		return "", fmt.Errorf("verify %s: %w", asset, err)
	}
	if progress != nil {
		progress("verified %s (%s)", asset, want[:12])
	}
	return staged, nil
}

func fetchChecksum(ctx context.Context, url string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", "gantry/"+Current())
	response, err := httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("download checksum: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download checksum: %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxChecksumSize+1))
	if err != nil {
		return "", fmt.Errorf("read checksum: %w", err)
	}
	if int64(len(body)) > maxChecksumSize {
		return "", fmt.Errorf("checksum response exceeds %d bytes", maxChecksumSize)
	}
	fields := strings.Fields(string(body))
	if len(fields) == 0 || len(fields[0]) != sha256.Size*2 {
		return "", fmt.Errorf("invalid sha256 sidecar")
	}
	if _, err := hex.DecodeString(fields[0]); err != nil {
		return "", fmt.Errorf("invalid sha256 sidecar: %w", err)
	}
	return strings.ToLower(fields[0]), nil
}

func platformAsset(goos, goarch string) (string, error) {
	extension := ""
	if goos == "windows" {
		extension = ".exe"
	}
	switch goos + "/" + goarch {
	case "linux/amd64", "linux/arm64", "darwin/arm64", "windows/amd64":
		return "gantry-" + goos + "-" + goarch + extension, nil
	default:
		return "", fmt.Errorf("self-update is not published for %s/%s", goos, goarch)
	}
}

func validateBinary(path, goos, goarch string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	header := make([]byte, 4096)
	n, err := io.ReadFull(file, header)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	header = header[:n]
	switch goos {
	case "linux":
		if len(header) < 20 || string(header[:4]) != "\x7fELF" || header[5] != 1 {
			return fmt.Errorf("not a little-endian ELF executable")
		}
		machine := binary.LittleEndian.Uint16(header[18:20])
		want := uint16(62)
		if goarch == "arm64" {
			want = 183
		}
		if machine != want {
			return fmt.Errorf("ELF machine %d does not match %s", machine, goarch)
		}
	case "darwin":
		if len(header) < 8 || binary.LittleEndian.Uint32(header[:4]) != 0xfeedfacf ||
			binary.LittleEndian.Uint32(header[4:8]) != 0x0100000c {
			return fmt.Errorf("not an arm64 Mach-O executable")
		}
	case "windows":
		if len(header) < 0x40 || string(header[:2]) != "MZ" {
			return fmt.Errorf("not a PE executable")
		}
		offset := int(binary.LittleEndian.Uint32(header[0x3c:0x40]))
		if offset < 0 || offset+6 > len(header) || string(header[offset:offset+4]) != "PE\x00\x00" ||
			binary.LittleEndian.Uint16(header[offset+4:offset+6]) != 0x8664 {
			return fmt.Errorf("not an amd64 PE executable")
		}
	default:
		return fmt.Errorf("unsupported executable format %s/%s", goos, goarch)
	}
	return nil
}

type progressReader struct {
	reader   io.Reader
	name     string
	total    int64
	read     int64
	last     time.Time
	report   func(string, ...any)
	complete bool
}

func (r *progressReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	r.read += int64(n)
	current := now()
	complete := r.total > 0 && r.read >= r.total
	if n > 0 && (r.last.IsZero() || complete || current.Sub(r.last) >= 100*time.Millisecond) {
		r.last = current
		r.emit(complete)
	}
	return n, err
}

func (r *progressReader) finish() {
	if !r.complete {
		r.emit(true)
	}
}

func (r *progressReader) emit(complete bool) {
	percent := 0
	if r.total > 0 {
		percent = int(r.read * 100 / r.total)
		if percent > 100 {
			percent = 100
		}
	} else if complete {
		percent = 100
	}
	filled := percent * 20 / 100
	bar := strings.Repeat("=", filled) + strings.Repeat("·", 20-filled)
	r.report("downloading %s [%s] %3d%%", r.name, bar, percent)
	r.complete = complete
}
