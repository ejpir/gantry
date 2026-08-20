//go:build linux || darwin

package sandbox

// spike_rootfs_prep.go — host preparation shared by Linux and macOS.
//
// prepareDirSnapshot builds the snapshot without mounts or privileges: the
// cached EROFS image is extracted with the pure-Go go-erofs reader and the
// spike fixtures are added directly. This models a native-snapshotter rootfs
// and is the macOS path; Linux prefers a real erofs+overlay mount and falls
// back to this when the kernel lacks either filesystem.

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ejpir/gantry/internal/sandbox/config"

	"github.com/erofs/go-erofs"
	"golang.org/x/sys/unix"
)

// pickStagingDir chooses the first candidate on a filesystem with user.*
// xattr support. The sandbox state dir can land on tmpfs (e.g. when HOME is
// unresolvable under SSM and layout.Root falls back to os.TempDir), and
// tmpfs before kernel 6.6 cannot store user xattrs — which would silently
// neuter the xattr check and misreport the export.
func pickStagingDir(preferred string) (string, error) {
	candidates := []string{preferred}
	for _, fb := range []string{"/var/tmp", os.TempDir()} {
		if fb != preferred {
			candidates = append(candidates, fb)
		}
	}
	var reasons []string
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		dir := filepath.Join(candidate, "gantry-rootfs-spike")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			reasons = append(reasons, fmt.Sprintf("%s: %v", dir, err))
			continue
		}
		probe, err := os.CreateTemp(dir, ".probe-")
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("%s: %v", dir, err))
			continue
		}
		name := probe.Name()
		_ = probe.Close()
		err = unix.Setxattr(name, "user.gantry_probe", []byte("1"), 0)
		_ = os.Remove(name)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("%s: no user xattrs: %v", dir, err))
			_ = os.Remove(dir)
			continue
		}
		if dir != preferred {
			fmt.Fprintf(os.Stderr, "gantry _rootfs-spike: staging on %s (%s lacks user-xattr support)\n", dir, preferred)
		}
		return dir, nil
	}
	return "", fmt.Errorf("no xattr-capable staging directory (%s)", strings.Join(reasons, "; "))
}

// prepareDirSnapshot extracts the cached image into a staging directory and
// populates it with the spike fixtures. staging must live on a filesystem
// with full user-xattr support (tmpfs would silently neuter the xattr
// check).
func prepareDirSnapshot(cfg config.RunConfig, staging string) (*rootfsSnapshotPrep, error) {
	if cfg.LayerSet != nil {
		return nil, fmt.Errorf("layerset images are not supported by the rootfs spike yet; use a flattened image")
	}
	if cfg.Image == "" {
		return nil, fmt.Errorf("no flattened image in the resolved configuration")
	}
	if _, err := os.Stat(cfg.Image); err != nil {
		return nil, fmt.Errorf("cached image: %w", err)
	}
	dir, err := os.MkdirTemp(staging, "gantry-rootfs-spike-")
	if err != nil {
		return nil, err
	}
	prep := &rootfsSnapshotPrep{
		dir:            dir,
		snapshot:       filepath.Join(dir, "snapshot"),
		writeVerifyDir: filepath.Join(dir, "snapshot"),
	}
	if err := os.Mkdir(prep.snapshot, 0o755); err != nil {
		prep.Cleanup()
		return nil, err
	}
	if err := prep.extractImage(cfg.Image); err != nil {
		prep.Cleanup()
		return nil, err
	}
	if err := prep.populateFixtures(prep.snapshot); err != nil {
		prep.Cleanup()
		return nil, err
	}
	return prep, nil
}

// extractImage unpacks the flattened EROFS image into the snapshot directory.
// Hard-linked image files arrive as independent copies and special files the
// host user cannot recreate are skipped — neither affects the transport
// semantics under test.
func (p *rootfsSnapshotPrep) extractImage(imagePath string) error {
	f, err := os.Open(imagePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	img, err := erofs.Open(f)
	if err != nil {
		return fmt.Errorf("open image as erofs: %w", err)
	}
	type readLinker interface{ ReadLink(string) (string, error) }
	linker, _ := img.(readLinker)

	var skipped int
	walkErr := fs.WalkDir(img, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dest := filepath.Join(p.snapshot, path)
		info, infoErr := d.Info()
		perm := fs.FileMode(0o755)
		if infoErr == nil {
			perm = info.Mode().Perm()
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(dest, perm)
		case d.Type()&fs.ModeSymlink != 0:
			if linker == nil {
				skipped++
				return nil
			}
			target, err := linker.ReadLink(path)
			if err != nil {
				return err
			}
			return os.Symlink(target, dest)
		case d.Type().IsRegular():
			return extractFile(img, path, dest, perm, info)
		default:
			// Device nodes and fifos need host privileges we may not have.
			skipped++
			return nil
		}
	})
	if walkErr != nil {
		return fmt.Errorf("extract image: %w", walkErr)
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "gantry _rootfs-spike: skipped %d special file(s) during extraction\n", skipped)
	}
	return nil
}

func extractFile(img fs.FS, path, dest string, perm fs.FileMode, info fs.FileInfo) error {
	src, err := img.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// Preserve mode bits beyond rwx (notably setuid) when the image carries
	// them and the host filesystem allows. go-erofs keeps the unix special
	// bits in the low mode bits of walk entries, so check both forms.
	if info != nil && info.Mode()&(fs.ModeSetuid|0o4000) != 0 {
		_ = os.Chmod(dest, perm|os.ModeSetuid)
	}
	return nil
}

// populateFixtures adds the files the guest checker asserts, plus the mount
// targets crun cannot create inside a host-enforced read-only export.
func (p *rootfsSnapshotPrep) populateFixtures(target string) error {
	if err := os.WriteFile(filepath.Join(target, "spike-upper-marker"), []byte("gantry-rootfs-spike\n"), 0o644); err != nil {
		return err
	}
	hardA := filepath.Join(target, "spike-hard-a")
	if err := os.WriteFile(hardA, []byte("hardlinked\n"), 0o644); err != nil {
		return err
	}
	if err := os.Link(hardA, filepath.Join(target, "spike-hard-b")); err != nil {
		return err
	}
	// Best effort: non-root hosts (macOS) cannot create device nodes; the
	// checker SKIPs the fixture check when the node is absent.
	if err := unix.Mknod(filepath.Join(target, "spike-dev-null"), unix.S_IFCHR|0o666, int(unix.Mkdev(1, 3))); err != nil {
		fmt.Fprintf(os.Stderr, "gantry _rootfs-spike: device-node fixture unavailable (checker will SKIP): %v\n", err)
	}
	if err := ensureMountTargets(target); err != nil {
		return err
	}
	return p.buildChecker(target)
}

// ensureMountTargets makes sure the snapshot carries every mount target the
// container config needs: a host-enforced read-only export rejects crun's
// target creation, so the targets must pre-exist.
func ensureMountTargets(target string) error {
	for _, dir := range []string{"proc", "dev", "dev/pts", "dev/shm", "dev/mqueue", "sys", "tmp"} {
		if err := os.MkdirAll(filepath.Join(target, dir), 0o755); err != nil {
			return err
		}
	}
	for _, file := range []string{"etc/hosts", "etc/resolv.conf"} {
		path := filepath.Join(target, file)
		if _, err := os.Stat(path); err == nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// buildChecker cross-compiles the static guest checker into the snapshot.
// The guest architecture always matches the host architecture in gantry.
// When GANTRY_SPIKECHECK_BIN names a prebuilt Linux checker for the host
// architecture it is copied instead of compiled: bare test instances (the
// AWS KVM rig) have no module tree, and runtime.Caller resolves to the
// build machine's path, which does not exist there.
func (p *rootfsSnapshotPrep) buildChecker(target string) error {
	checker := filepath.Join(target, "spikecheck")
	if pre := os.Getenv("GANTRY_SPIKECHECK_BIN"); pre != "" {
		payload, err := os.ReadFile(pre)
		if err != nil {
			return fmt.Errorf("read prebuilt checker (GANTRY_SPIKECHECK_BIN): %w", err)
		}
		if err := os.WriteFile(checker, payload, 0o755); err != nil {
			return err
		}
		return placeSetuidCopy(target, checker)
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("the rootfs spike needs a Go toolchain to build the guest checker: %w", err)
	}
	var goarch string
	switch runtime.GOARCH {
	case "amd64", "arm64":
		goarch = runtime.GOARCH
	default:
		return fmt.Errorf("unsupported host architecture for the guest checker: %s", runtime.GOARCH)
	}
	_, thisFile, _, _ := runtime.Caller(0)
	moduleRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	build := exec.Command(goTool, "build", "-o", checker, "./internal/spikecheck")
	build.Dir = moduleRoot
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("build guest checker: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return placeSetuidCopy(target, checker)
}

// placeSetuidCopy installs the setuid fixture next to the checker binary.
func placeSetuidCopy(target, checker string) error {
	payload, err := os.ReadFile(checker)
	if err != nil {
		return err
	}
	setuid := filepath.Join(target, "spike-setuid")
	if err := os.WriteFile(setuid, payload, 0o755); err != nil {
		return err
	}
	// os.FileMode carries setuid as os.ModeSetuid, not the unix 0o4000 bit.
	return os.Chmod(setuid, 0o755|os.ModeSetuid)
}
