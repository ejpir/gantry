package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// loadImageArchive accepts both Docker save archives and standard OCI
// image-layout tar archives. OCI archives are extracted only into Gantry's
// private image staging area and are then processed by the same digest-
// verifying OCI layout loader used for directory sources.
func loadImageArchive(archivePath, ref, arch string, newTempDir func() (string, error)) (*pulled, error) {
	isOCI, err := isOCIArchive(archivePath)
	if err != nil {
		return nil, err
	}
	if !isOCI {
		return loadDockerSave(archivePath, ref, arch, newTempDir)
	}
	return loadOCIArchive(archivePath, ref, arch, newTempDir)
}

func isOCIArchive(archivePath string) (bool, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return false, err
	}
	defer func() { _ = file.Close() }()
	reader := tar.NewReader(file)
	layout, index := false, false
	for members := 0; ; members++ {
		if members > 100000 {
			return false, fmt.Errorf("%s: archive has too many members", archivePath)
		}
		header, err := reader.Next()
		if err == io.EOF {
			return layout && index, nil
		}
		if err != nil {
			return false, fmt.Errorf("read %s: %w", archivePath, err)
		}
		name := strings.TrimPrefix(header.Name, "./")
		layout = layout || name == "oci-layout"
		index = index || name == "index.json"
	}
}

func loadOCIArchive(archivePath, ref, arch string, newTempDir func() (string, error)) (*pulled, error) {
	staging, err := newTempDir()
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = os.RemoveAll(staging)
		}
	}()
	file, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	reader := tar.NewReader(file)
	seen := map[string]bool{}
	for members := 0; ; members++ {
		if members > 100000 {
			return nil, fmt.Errorf("%s: archive has too many members", archivePath)
		}
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", archivePath, err)
		}
		name := strings.TrimPrefix(header.Name, "./")
		clean := path.Clean(name)
		if clean != name || clean == "." || path.IsAbs(clean) || strings.HasPrefix(clean, "../") || strings.Contains(clean, `\`) {
			return nil, fmt.Errorf("%s: unsafe OCI archive member %q", archivePath, header.Name)
		}
		wanted := clean == "oci-layout" || clean == "index.json" || validOCIBlobName(clean)
		if !wanted {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != 0 {
			return nil, fmt.Errorf("%s: OCI member %s is not a regular file", archivePath, clean)
		}
		if seen[clean] {
			return nil, fmt.Errorf("%s: duplicate OCI member %s", archivePath, clean)
		}
		seen[clean] = true
		if (clean == "oci-layout" || clean == "index.json") && header.Size > 16<<20 {
			return nil, fmt.Errorf("%s: metadata member %s is too large", archivePath, clean)
		}
		destination := filepath.Join(staging, filepath.FromSlash(clean))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return nil, err
		}
		output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		written, copyErr := io.CopyN(output, reader, header.Size)
		closeErr := output.Close()
		if copyErr != nil {
			return nil, errors.Join(fmt.Errorf("extract %s: %w", clean, copyErr), closeErr)
		}
		if written != header.Size {
			return nil, fmt.Errorf("extract %s: wrote %d of %d bytes", clean, written, header.Size)
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	if !seen["oci-layout"] || !seen["index.json"] {
		return nil, fmt.Errorf("%s: incomplete OCI archive", archivePath)
	}
	layersDir := filepath.Join(staging, "unpacked")
	if err := os.Mkdir(layersDir, 0o700); err != nil {
		return nil, err
	}
	result, err := loadOCILayout(staging, ref, arch, func() (string, error) {
		return os.MkdirTemp(layersDir, "layers-")
	})
	if err != nil {
		return nil, err
	}
	// The pulled value normally owns only its decompression directory. Here it
	// owns the containing extraction tree as well, so one Close removes both.
	result.tmpDir = staging
	failed = false
	return result, nil
}

func validOCIBlobName(name string) bool {
	const prefix = "blobs/sha256/"
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	hex := strings.TrimPrefix(name, prefix)
	if len(hex) != 64 || strings.Contains(hex, "/") {
		return false
	}
	for index := range hex {
		if (hex[index] < '0' || hex[index] > '9') && (hex[index] < 'a' || hex[index] > 'f') {
			return false
		}
	}
	return true
}
