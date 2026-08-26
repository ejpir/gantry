package rwlayer

// rwlayer.go — the writable-layer lifecycle: per-sandbox defaults,
// creation without root, image pairing, and host-side health checks.
//
// Why this exists: the shared ./rwlayer.ext4 default let two live VMs
// attach one ext4 (two guest kernels, two allocators, one set of block
// bitmaps → silent corruption surfacing as overlay ESTALE), and it let
// an upper populated by one image ride over another image's lower
// (overlayfs origin verification → ESTALE again). Both are now
// structural: writable disks are exclusively locked (vblk), the default is
// per-sandbox, and the pairing is recorded and enforced.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	backendfile "github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/ext4"
	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// Root is ~/.gantry/rwlayers (sibling of the sandboxes dir so a
// `gantry start` state wipe never deletes user data).
func Root() string {
	return filepath.Join(filepath.Dir(layout.Root()), "rwlayers")
}

// Path is the per-sandbox default location.
func Path(name string) string {
	return filepath.Join(Root(), name+".ext4")
}

// pairingPath is the sidecar recording which image the layer was
// built against.
func pairingPath(layer string) string { return layer + ".image" }

// Default returns the per-sandbox rwlayer, creating it on first
// use. Pairing is checked by the caller (CheckPairing).
func Default(name, imageID string, sizeMiB uint, progress func(string, ...any)) (string, []string, error) {
	p := Path(name)
	if gutil.FileExists(p) {
		// Layers hold persistent filesystem data: 0600/0700 now, but
		// older gantry versions created them 0644/0755 — tighten on use
		// (review finding 6). Best-effort.
		_ = os.Chmod(Root(), 0o700)
		_ = os.Chmod(p, 0o600)
		_ = os.Chmod(pairingPath(p), 0o600)
		return p, nil, nil
	}
	if err := os.MkdirAll(Root(), 0o700); err != nil {
		return "", nil, err
	}
	warns, err := create(p, sizeMiB, progress)
	if err != nil {
		return "", nil, fmt.Errorf("creating rwlayer %s: %w", p, err)
	}
	return p, warns, nil
}

// create makes a sparse ext4 filesystem with the /upper and /work
// directories overlayfs needs. Formatting and directory creation are pure Go:
// hosts do not need e2fsprogs, root privileges, or a mounted loop device.
// A complete temporary image is synced and then published with no-replace
// semantics, so interruption or concurrent starts cannot expose a partial
// persistent disk.
func create(path string, sizeMiB uint, progress func(string, ...any)) (retWarnings []string, retErr error) {
	if err := config.ValidateRWLayerSize(sizeMiB); err != nil {
		return nil, err
	}
	reportProgress(progress, sizeMiB, 0)

	tmp, err := os.CreateTemp(filepath.Dir(path), ".rwlayer-*.ext4")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	// backend/file creates with O_EXCL so it cannot inherit stale contents.
	if err := os.Remove(tmpPath); err != nil {
		return nil, err
	}
	defer func() {
		if err := os.Remove(tmpPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			retErr = errors.Join(retErr, fmt.Errorf("remove temporary rwlayer: %w", err))
		}
	}()

	sizeBytes := int64(sizeMiB) << 20
	storage, err := backendfile.CreateFromPath(tmpPath, sizeBytes)
	if err != nil {
		return nil, err
	}
	storageOpen := true
	defer func() {
		if storageOpen {
			retErr = errors.Join(retErr, storage.Close())
		}
	}()
	reportProgress(progress, sizeMiB, 10)
	fs, err := ext4.Create(storage, sizeBytes, 0, 512, &ext4.Params{VolumeName: "rwlayer"})
	if err != nil {
		return nil, fmt.Errorf("format ext4: %w", err)
	}
	reportProgress(progress, sizeMiB, 90)
	for _, dir := range []string{"upper", "work"} {
		if err := fs.Mkdir(dir); err != nil {
			return nil, fmt.Errorf("create /%s: %w", dir, err)
		}
	}
	if err := fs.Close(); err != nil {
		return nil, fmt.Errorf("close ext4: %w", err)
	}
	if file, err := storage.Sys(); err == nil {
		if err := file.Sync(); err != nil {
			return nil, fmt.Errorf("sync ext4: %w", err)
		}
	}
	if err := storage.Close(); err != nil {
		return nil, fmt.Errorf("close rwlayer: %w", err)
	}
	storageOpen = false
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return nil, err
	}
	if err := os.Link(tmpPath, path); err != nil {
		return nil, fmt.Errorf("publish rwlayer: %w", err)
	}
	reportProgress(progress, sizeMiB, 100)
	return nil, nil
}

func reportProgress(progress func(string, ...any), sizeMiB uint, percent int) {
	if progress == nil {
		return
	}
	const width = 20
	filled := percent * width / 100
	bar := strings.Repeat("=", filled) + strings.Repeat("·", width-filled)
	progress("creating persistent disk [%s] %3d%% (%d MiB)", bar, percent, sizeMiB)
}

// CheckPairing refuses to attach a layer whose recorded image
// differs from the current one: an upper populated from image A is
// semantically wrong over image B's lower, and overlayfs origin
// verification turns that into ESTALE.
func CheckPairing(layer, imageID string) error {
	pp := pairingPath(layer)
	b, err := os.ReadFile(pp)
	if errors.Is(err, os.ErrNotExist) {
		// A legacy or hand-made layer has no record yet. Install one before
		// attachment so a crash cannot leave an ambiguous partial sidecar.
		return WritePairing(layer, imageID)
	}
	if err != nil {
		return fmt.Errorf("read rwlayer pairing %s: %w", pp, err)
	}
	var rec struct {
		Image string `json:"image"`
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return fmt.Errorf("rwlayer pairing %s is malformed: %w", pp, err)
	}
	if rec.Image == "" {
		return fmt.Errorf("rwlayer pairing %s has no image identity", pp)
	}
	if rec.Image != imageID {
		return fmt.Errorf(`rwlayer %s was built against image
  %s
but this sandbox uses
  %s
An upper layer is per-image: delete the sandbox, remove %s,
or point -rwlayer at a different file`,
			layer, rec.Image, imageID, pp)
	}
	return nil
}

// WritePairing durably installs the pairing sidecar. It is written only
// when a layer is created or adopted, not on the normal startup path.
func WritePairing(layer, imageID string) error {
	b, err := json.Marshal(struct {
		Image string `json:"image"`
	}{imageID})
	if err != nil {
		return fmt.Errorf("encode rwlayer pairing: %w", err)
	}
	if err := atomicfile.WriteFileDurable(pairingPath(layer), append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write rwlayer pairing: %w", err)
	}
	return nil
}

// HealthWarning reads the ext4 superblock and reports recorded
// filesystem errors — the honest version of the "looks corrupted" hint.
// Only a nonzero error count warns: the state bit alone lingers after
// repairs and means nothing without recorded errors.
func HealthWarning(path string) string {
	info, err := gutil.ProbeExt4(path)
	if err != nil {
		return "" // not ext4 (or unreadable): the guest mount will say so
	}
	if info.ErrorCount == 0 {
		return ""
	}
	return fmt.Sprintf("rwlayer %s: %s\nit mounts, but consider recreating it: ./scripts/mkrwlayer.sh %s 512", path, info.Diagnosis(), path)
}

// @ is intentionally outside the sandbox-name alphabet, so an IDE layer can
// never alias the primary layer of another valid sandbox name.
const devContainersLayerSuffix = "@devcontainers"

// DevContainersName is the managed writable-layer identity for the curated
// IDE environment that shares a VM with the named workload sandbox.
func DevContainersName(name string) string { return name + devContainersLayerSuffix }

// Forget removes a sandbox's managed workload and IDE layers plus sidecars.
func Forget(name string) {
	for _, managedName := range []string{name, DevContainersName(name)} {
		_ = os.Remove(Path(managedName))
		_ = os.Remove(pairingPath(Path(managedName)))
	}
}
