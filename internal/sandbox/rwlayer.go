package sandbox

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
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/gutil"
)

// blankRWLayer is a 512 MiB ext4 with /upper + /work, gzipped (~0.5 MB).
// Deterministic, built by scripts/mkblankrwlayer.sh; embedded so per-sandbox
// layers need no host e2fsprogs (stock macOS has none).
//
//go:embed assets/blank.ext4.gz
var blankRWLayer []byte

// rwlayersRoot is ~/.gantry/rwlayers (sibling of the sandboxes dir so a
// `gantry start` state wipe never deletes user data).
func rwlayersRoot() string {
	return filepath.Join(filepath.Dir(sandboxRoot()), "rwlayers")
}

// defaultRWLayerPath is the per-sandbox default location.
func defaultRWLayerPath(name string) string {
	return filepath.Join(rwlayersRoot(), name+".ext4")
}

// rwlayerPairingPath is the sidecar recording which image the layer was
// built against.
func rwlayerPairingPath(layer string) string { return layer + ".image" }

// defaultRWLayer returns the per-sandbox rwlayer, creating it on first
// use. Pairing is checked by the caller (checkRWLayerPairing).
func defaultRWLayer(name, imageID string) (string, []string, error) {
	p := defaultRWLayerPath(name)
	if gutil.FileExists(p) {
		// Layers hold persistent filesystem data: 0600/0700 now, but
		// older gantry versions created them 0644/0755 — tighten on use
		// (review finding 6). Best-effort.
		_ = os.Chmod(rwlayersRoot(), 0o700)
		_ = os.Chmod(p, 0o600)
		_ = os.Chmod(rwlayerPairingPath(p), 0o600)
		return p, nil, nil
	}
	if err := os.MkdirAll(rwlayersRoot(), 0o700); err != nil {
		return "", nil, err
	}
	warns, err := createRWLayer(p)
	if err != nil {
		return "", nil, fmt.Errorf("creating rwlayer %s: %w\n(create it manually with ./scripts/mkrwlayer.sh %s 512)", p, err, p)
	}
	return p, warns, nil
}

// createRWLayer makes a 512 MiB sparse ext4 with the /upper and /work
// directories overlayfs needs — without root. Strategy: host e2fsprogs
// when present (mkfs.ext4 + debugfs); otherwise inflate the embedded
// blank template. (An earlier revision cloned ./rwlayer.ext4 instead —
// that cloned whatever damage the shared layer already had, and
// SEEK_HOLE is unreliable on shared-repo filesystems. Deterministic or
// nothing.)
func createRWLayer(path string) ([]string, error) {
	mkfs, err1 := exec.LookPath("mkfs.ext4")
	debugfs, err2 := exec.LookPath("debugfs")
	if err1 == nil && err2 == nil {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		if err := f.Truncate(512 << 20); err != nil {
			_ = f.Close()
			return nil, err
		}
		_ = f.Close()
		if out, err := exec.Command(mkfs, "-q", "-F", "-L", "rwlayer", path).CombinedOutput(); err != nil {
			_ = os.Remove(path)
			return nil, fmt.Errorf("mkfs.ext4: %v: %s", err, out)
		}
		for _, dir := range []string{"/upper", "/work"} {
			if out, err := exec.Command(debugfs, "-w", "-R", "mkdir "+dir, path).CombinedOutput(); err != nil {
				_ = os.Remove(path)
				return nil, fmt.Errorf("debugfs mkdir %s: %v: %s", dir, err, out)
			}
		}
		return nil, nil
	}
	if err := inflateBlankRWLayer(path); err != nil {
		return nil, err
	}
	return nil, nil
}

// inflateBlankRWLayer writes the embedded blank ext4 to path, sparsely
// (zero 1 MiB chunks are skipped, so the 512 MiB layer costs only its
// real metadata).
func inflateBlankRWLayer(path string) error {
	gz, err := gzip.NewReader(bytes.NewReader(blankRWLayer))
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	out, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	var off int64
	for {
		n, err := io.ReadFull(gz, buf)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			_ = out.Close()
			_ = os.Remove(path)
			return err
		}
		chunk := buf[:n]
		if !allZero(chunk) {
			if _, werr := out.WriteAt(chunk, off); werr != nil {
				_ = out.Close()
				_ = os.Remove(path)
				return werr
			}
		}
		off += int64(n)
	}
	if err := out.Truncate(off); err != nil {
		_ = out.Close()
		_ = os.Remove(path)
		return err
	}
	return out.Close()
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// checkRWLayerPairing refuses to attach a layer whose recorded image
// differs from the current one: an upper populated from image A is
// semantically wrong over image B's lower, and overlayfs origin
// verification turns that into ESTALE.
func checkRWLayerPairing(layer, imageID string) error {
	pp := rwlayerPairingPath(layer)
	b, err := os.ReadFile(pp)
	if errors.Is(err, os.ErrNotExist) {
		// A legacy or hand-made layer has no record yet. Install one before
		// attachment so a crash cannot leave an ambiguous partial sidecar.
		return writeRWLayerPairing(layer, imageID)
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

// writeRWLayerPairing durably installs the pairing sidecar. It is written only
// when a layer is created or adopted, not on the normal startup path.
func writeRWLayerPairing(layer, imageID string) error {
	b, err := json.Marshal(struct {
		Image string `json:"image"`
	}{imageID})
	if err != nil {
		return fmt.Errorf("encode rwlayer pairing: %w", err)
	}
	if err := atomicfile.WriteFileDurable(rwlayerPairingPath(layer), append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write rwlayer pairing: %w", err)
	}
	return nil
}

// rwlayerHealthWarning reads the ext4 superblock and reports recorded
// filesystem errors — the honest version of the "looks corrupted" hint.
// Only a nonzero error count warns: the state bit alone lingers after
// repairs and means nothing without recorded errors.
func rwlayerHealthWarning(path string) string {
	info, err := gutil.ProbeExt4(path)
	if err != nil {
		return "" // not ext4 (or unreadable): the guest mount will say so
	}
	if info.ErrorCount == 0 {
		return ""
	}
	return fmt.Sprintf("rwlayer %s: %s\nit mounts, but consider recreating it: ./scripts/mkrwlayer.sh %s 512", path, info.Diagnosis(), path)
}

// forgetRWLayer removes a sandbox's default layer + sidecar (delete).
func forgetRWLayer(name string) {
	_ = os.Remove(defaultRWLayerPath(name))
	_ = os.Remove(rwlayerPairingPath(defaultRWLayerPath(name)))
}
