package sandbox

// rwlayer.go — the writable-layer lifecycle: per-sandbox defaults,
// creation without root, image pairing, and host-side health checks.
//
// Why this exists: the shared ./rwlayer.ext4 default let two live VMs
// attach one ext4 (two guest kernels, two allocators, one set of block
// bitmaps → silent corruption surfacing as overlay ESTALE), and it let
// an upper populated by one image ride over another image's lower
// (overlayfs origin verification → ESTALE again). Both are now
// structural: writable disks are flock'd (vblk), the default is
// per-sandbox, and the pairing is recorded and enforced.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"gantry/internal/gutil"
)

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
		return p, nil, nil
	}
	if err := os.MkdirAll(rwlayersRoot(), 0o755); err != nil {
		return "", nil, err
	}
	warns, err := createRWLayer(p)
	if err != nil {
		return "", nil, fmt.Errorf("creating rwlayer %s: %w\n(create it manually with ./mkrwlayer.sh %s 512)", p, err, p)
	}
	return p, warns, nil
}

// createRWLayer makes a 512 MiB sparse ext4 with the /upper and /work
// directories overlayfs needs — without root. Strategy: host e2fsprogs
// when present (mkfs.ext4 + debugfs); otherwise clone the legacy
// ./rwlayer.ext4 template if one exists (it is itself a valid blank
// layer for a fresh sandbox).
func createRWLayer(path string) ([]string, error) {
	mkfs, err1 := exec.LookPath("mkfs.ext4")
	debugfs, err2 := exec.LookPath("debugfs")
	if err1 == nil && err2 == nil {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
		if err != nil {
			return nil, err
		}
		if err := f.Truncate(512 << 20); err != nil {
			f.Close()
			return nil, err
		}
		f.Close()
		if out, err := exec.Command(mkfs, "-q", "-F", "-L", "rwlayer", path).CombinedOutput(); err != nil {
			os.Remove(path)
			return nil, fmt.Errorf("mkfs.ext4: %v: %s", err, out)
		}
		for _, dir := range []string{"/upper", "/work"} {
			if out, err := exec.Command(debugfs, "-w", "-R", "mkdir "+dir, path).CombinedOutput(); err != nil {
				os.Remove(path)
				return nil, fmt.Errorf("debugfs mkdir %s: %v: %s", dir, err, out)
			}
		}
		return nil, nil
	}
	// no e2fsprogs (stock macOS): clone the legacy template
	if gutil.FileExists("rwlayer.ext4") {
		if err := copySparse("rwlayer.ext4", path); err != nil {
			return nil, err
		}
		return []string{"created " + path + " from the ./rwlayer.ext4 template (install e2fsprogs to build fresh layers)"}, nil
	}
	return nil, fmt.Errorf("mkfs.ext4/debugfs not found and no ./rwlayer.ext4 template to clone")
}

// checkRWLayerPairing refuses to attach a layer whose recorded image
// differs from the current one: an upper populated from image A is
// semantically wrong over image B's lower, and overlayfs origin
// verification turns that into ESTALE.
func checkRWLayerPairing(layer, imageID string) error {
	pp := rwlayerPairingPath(layer)
	b, err := os.ReadFile(pp)
	if err != nil {
		// no sidecar: legacy or hand-made layer — record and move on
		writeRWLayerPairing(layer, imageID)
		return nil
	}
	var rec struct {
		Image string `json:"image"`
	}
	if json.Unmarshal(b, &rec) != nil || rec.Image == "" {
		writeRWLayerPairing(layer, imageID)
		return nil
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

// writeRWLayerPairing records the pairing sidecar (best-effort).
func writeRWLayerPairing(layer, imageID string) {
	b, _ := json.Marshal(struct {
		Image string `json:"image"`
	}{imageID})
	os.WriteFile(rwlayerPairingPath(layer), b, 0o644)
}

// rwlayerHealthWarning reads the ext4 superblock and reports recorded
// filesystem errors — the honest version of the "looks corrupted" hint.
func rwlayerHealthWarning(path string) string {
	info, err := gutil.ProbeExt4(path)
	if err != nil {
		return "" // not ext4 (or unreadable): the guest mount will say so
	}
	if info.ErrorCount == 0 && info.State&gutil.Ext4StateError == 0 {
		return ""
	}
	return fmt.Sprintf("rwlayer %s: %s\nit mounts, but consider recreating it: ./mkrwlayer.sh %s 512", path, info.Diagnosis(), path)
}

// forgetRWLayer removes a sandbox's default layer + sidecar (delete).
func forgetRWLayer(name string) {
	os.Remove(defaultRWLayerPath(name))
	os.Remove(rwlayerPairingPath(defaultRWLayerPath(name)))
}
