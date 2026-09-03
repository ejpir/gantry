package devcontainers

import (
	"archive/tar"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/image"
	erofs "github.com/erofs/go-erofs"
)

func writeToolingImage(t *testing.T, omit string) string {
	t.Helper()
	layer, err := os.CreateTemp(t.TempDir(), "tooling-*.tar")
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(layer)
	for _, name := range []string{
		"usr/local/bin/podman",
		"usr/local/libexec/gantry-podman",
		"usr/bin/podman",
	} {
		if name == omit {
			continue
		}
		contents := []byte("#!/bin/sh\nexit 0\n")
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(contents)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := layer.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = layer.Close() })
	path := filepath.Join(t.TempDir(), "ide.erofs")
	if _, err := image.Build(path, []*os.File{layer}, nil, nil); err != nil {
		t.Fatal(err)
	}
	return path
}

func markImageCompressed(t *testing.T, path string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	var features [6]byte
	if _, err := file.ReadAt(features[:], erofsSuperBlockOffset+erofsFeatureIncompatOffset); err != nil {
		t.Fatal(err)
	}
	incompat := binary.LittleEndian.Uint32(features[:4]) | erofsFeatureLZ4ZeroPadding
	binary.LittleEndian.PutUint32(features[:4], incompat)
	binary.LittleEndian.PutUint16(features[4:], 1)
	if _, err := file.WriteAt(features[:], erofsSuperBlockOffset+erofsFeatureIncompatOffset); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyImageRequiresCuratedPodmanTooling(t *testing.T) {
	if err := VerifyImage(writeToolingImage(t, "")); err != nil {
		t.Fatalf("complete curated image rejected: %v", err)
	}
	missing := "usr/local/libexec/gantry-podman"
	if err := VerifyImage(writeToolingImage(t, missing)); err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("missing launcher error = %v", err)
	}
}

func TestVerifyImageSupportsCompressedFilesystemMetadata(t *testing.T) {
	path := writeToolingImage(t, "")
	markImageCompressed(t, path)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, openErr := erofs.Open(file)
	_ = file.Close()
	if !errors.Is(openErr, erofs.ErrNotImplemented) {
		t.Fatalf("ordinary go-erofs open error = %v, want compression not implemented", openErr)
	}
	if err := VerifyImage(path); err != nil {
		t.Fatalf("compressed curated image rejected: %v", err)
	}

	missing := "usr/bin/podman"
	missingPath := writeToolingImage(t, missing)
	markImageCompressed(t, missingPath)
	if err := VerifyImage(missingPath); err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("compressed image missing-tool error = %v", err)
	}
}
