package devcontainers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"

	"github.com/ejpir/gantry/internal/guestasset"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/rwlayer"
	erofs "github.com/erofs/go-erofs"
)

// Dependencies are the host-side asset and writable-layer operations used to
// prepare the curated IDE environment. Production callers use Prepare;
// PrepareWith keeps failure paths deterministic in package tests.
type Dependencies struct {
	EnsureImage  func(string, func(string, ...any)) (string, error)
	VerifyImage  func(string) error
	EnsureLayer  func(string, string, uint, func(string, ...any)) (string, []string, error)
	CheckPairing func(string, string) error
}

func defaultDependencies() Dependencies {
	return Dependencies{
		EnsureImage:  guestasset.EnsureImage,
		VerifyImage:  VerifyImage,
		EnsureLayer:  rwlayer.Default,
		CheckPairing: rwlayer.CheckPairing,
	}
}

// ImageConfig is the known OCI metadata of the curated IDE image. The release
// asset is flattened to EROFS, so this metadata cannot be recovered from the
// filesystem itself.
func ImageConfig() *image.Config {
	return &image.Config{
		Env: []string{
			"HOME=/home/gantry",
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		},
		Cmd: []string{"/bin/bash"}, User: "gantry", UID: 1000, GID: 1000,
		WorkingDir: "/home/gantry",
	}
}

// CuratedImageConfig restores metadata only for the canonical curated release
// asset; ordinary EROFS workload files retain their existing behavior.
func CuratedImageConfig(path string) *image.Config {
	if filepath.Base(path) != filepath.Base(guestasset.DefaultDevContainersImage()) {
		return nil
	}
	return ImageConfig()
}

const (
	erofsSuperBlockOffset      = int64(1024)
	erofsSuperBlockSize        = 128
	erofsFeatureIncompatOffset = 80
	erofsCompressionAlgsOffset = 84
	erofsFeatureLZ4ZeroPadding = uint32(0x1)
)

// erofsMetadataReaderAt lets go-erofs traverse metadata in an image containing
// compressed regular files. go-erofs can decode those inodes and directories
// for Stat, but currently rejects the whole filesystem at Open because it
// cannot read compressed file contents. Present a copy of the superblock with
// only the compression indicators hidden; every metadata/data read after Open
// still comes from the original image. A compressed directory remains
// unreadable and therefore fails verification closed.
type erofsMetadataReaderAt struct{ io.ReaderAt }

func (reader erofsMetadataReaderAt) ReadAt(buffer []byte, offset int64) (int, error) {
	n, err := reader.ReaderAt.ReadAt(buffer, offset)
	if offset != erofsSuperBlockOffset || len(buffer) != erofsSuperBlockSize || n != erofsSuperBlockSize {
		return n, err
	}
	incompat := binary.LittleEndian.Uint32(buffer[erofsFeatureIncompatOffset:])
	binary.LittleEndian.PutUint32(buffer[erofsFeatureIncompatOffset:], incompat&^erofsFeatureLZ4ZeroPadding)
	binary.LittleEndian.PutUint16(buffer[erofsCompressionAlgsOffset:], 0)
	return n, err
}

func openEROFSMetadata(file *os.File) (fs.FS, error) {
	root, err := erofs.Open(file)
	if err == nil || !errors.Is(err, erofs.ErrNotImplemented) {
		return root, err
	}
	metadataRoot, metadataErr := erofs.Open(erofsMetadataReaderAt{ReaderAt: file})
	if metadataErr != nil {
		return nil, fmt.Errorf("%v; metadata-only open: %w", err, metadataErr)
	}
	return metadataRoot, nil
}

// VerifyImage confirms that the flattened curated root actually carries the
// Podman wrapper, its privileged launcher, and the packaged Podman binary.
// Verification only needs inode names, types, and modes, so compressed release
// images do not require host-side decompression support.
func VerifyImage(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	root, err := openEROFSMetadata(file)
	if err != nil {
		return fmt.Errorf("open curated image: %w", err)
	}
	for _, executable := range []string{
		"usr/local/bin/podman",
		"usr/local/libexec/gantry-podman",
		"usr/bin/podman",
	} {
		info, err := fs.Stat(root, executable)
		if err != nil {
			return fmt.Errorf("curated image lacks %s: %w", executable, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("curated image %s is not executable", executable)
		}
	}
	return nil
}

// ProfileUpdate converts a prepared configuration into the atomic store
// update used to enable Dev Containers.
func ProfileUpdate(cfg config.RunConfig) *config.DevContainersProfileUpdate {
	return &config.DevContainersProfileUpdate{
		Image: cfg.DevContainersImage, ImageCfg: cfg.DevContainersImageCfg,
		RWLayer: cfg.DevContainersRWLayer, DiskMiB: cfg.DevContainersDiskMiB,
	}
}

// Prepare resolves and verifies the curated image and its paired persistent
// writable layer before a Dev Containers profile is committed.
func Prepare(name string, cfg config.RunConfig, progress func(string, ...any)) (config.RunConfig, bool, []string, error) {
	return PrepareWith(name, cfg, progress, defaultDependencies())
}

// PrepareWith is Prepare with explicit host-side dependencies.
func PrepareWith(name string, cfg config.RunConfig, progress func(string, ...any), dependencies Dependencies) (config.RunConfig, bool, []string, error) {
	if !cfg.DevContainers {
		return cfg, false, nil, nil
	}
	if name == "" {
		return cfg, false, nil, fmt.Errorf("dev containers require a named persistent sandbox")
	}
	before := cfg

	// Pin an existing IDE lower layer just like a workload image. Silently
	// replacing it on every Gantry update would invalidate the paired overlay
	// and strand persistent Podman images and editor state.
	ideImage := cfg.DevContainersImage
	if ideImage != "" {
		if _, err := os.Stat(ideImage); err != nil && !os.IsNotExist(err) {
			return before, false, nil, fmt.Errorf("inspect curated Dev Containers image: %w", err)
		} else if os.IsNotExist(err) {
			ideImage = ""
		}
	}
	if ideImage == "" {
		var err error
		ideImage, err = dependencies.EnsureImage(guestasset.DefaultDevContainersImage(), progress)
		if err != nil {
			return before, false, nil, fmt.Errorf("prepare curated Dev Containers image: %w", err)
		}
	}
	var err error
	ideImage, err = filepath.Abs(ideImage)
	if err != nil {
		return before, false, nil, fmt.Errorf("resolve curated Dev Containers image: %w", err)
	}
	if err := dependencies.VerifyImage(ideImage); err != nil {
		return before, false, nil, fmt.Errorf("verify curated Dev Containers Podman tooling: %w", err)
	}
	cfg.DevContainersImage = ideImage
	cfg.DevContainersImageCfg = ImageConfig()

	diskMiB := cfg.DevContainersDiskMiB
	if diskMiB == 0 {
		diskMiB = cfg.RWLayerSizeMiB
	}
	if diskMiB == 0 {
		diskMiB = config.DefaultDevContainersDiskSizeMiB
	}
	if err := config.ValidateRWLayerSize(diskMiB); err != nil {
		return before, false, nil, fmt.Errorf("dev containers writable layer: %w", err)
	}
	layer, warnings, err := dependencies.EnsureLayer(
		rwlayer.DevContainersName(name), ideImage, diskMiB, progress)
	if err != nil {
		return before, false, warnings, fmt.Errorf("prepare Dev Containers writable layer: %w", err)
	}
	layer, err = filepath.Abs(layer)
	if err != nil {
		return before, false, warnings, fmt.Errorf("resolve Dev Containers writable layer: %w", err)
	}
	if warning := rwlayer.HealthWarning(layer); warning != "" {
		warnings = append(warnings, warning)
	}
	if err := dependencies.CheckPairing(layer, ideImage); err != nil {
		return before, false, warnings, fmt.Errorf("dev containers writable layer: %w", err)
	}
	cfg.DevContainersRWLayer = layer
	cfg.DevContainersDiskMiB = diskMiB

	changed := before.DevContainersImage != cfg.DevContainersImage ||
		before.DevContainersRWLayer != cfg.DevContainersRWLayer ||
		before.DevContainersDiskMiB != cfg.DevContainersDiskMiB ||
		!reflect.DeepEqual(before.DevContainersImageCfg, cfg.DevContainersImageCfg)
	return cfg, changed, warnings, nil
}
