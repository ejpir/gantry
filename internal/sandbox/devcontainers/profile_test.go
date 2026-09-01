package devcontainers

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/image"
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

func TestVerifyImageRequiresCuratedPodmanTooling(t *testing.T) {
	if err := VerifyImage(writeToolingImage(t, "")); err != nil {
		t.Fatalf("complete curated image rejected: %v", err)
	}
	missing := "usr/local/libexec/gantry-podman"
	if err := VerifyImage(writeToolingImage(t, missing)); err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("missing launcher error = %v", err)
	}
}
