package image

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOCIArchiveImportRejectsUnsafeMember(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "unsafe.oci.tar")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	for _, header := range []*tar.Header{
		{Name: "oci-layout", Typeflag: tar.TypeReg, Mode: 0o644, Size: 0},
		{Name: "index.json", Typeflag: tar.TypeReg, Mode: 0o644, Size: 0},
		{Name: "../blobs/sha256/" + strings.Repeat("a", 64), Typeflag: tar.TypeReg, Mode: 0o644, Size: 0},
	} {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = ImportArchive(archive, "safe/name:latest", "amd64", NewStore(filepath.Join(t.TempDir(), "store")), nil)
	if err == nil || !strings.Contains(err.Error(), "unsafe OCI archive member") {
		t.Fatalf("unsafe archive error = %v", err)
	}
}

func TestValidOCIBlobName(t *testing.T) {
	if !validOCIBlobName("blobs/sha256/" + strings.Repeat("0", 64)) {
		t.Fatal("valid blob name rejected")
	}
	for _, name := range []string{
		"blobs/sha256/short",
		"blobs/sha512/" + strings.Repeat("0", 64),
		"blobs/sha256/" + strings.Repeat("g", 64),
		"../blobs/sha256/" + strings.Repeat("0", 64),
	} {
		if validOCIBlobName(name) {
			t.Errorf("invalid blob name accepted: %q", name)
		}
	}
}
