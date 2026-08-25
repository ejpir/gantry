package sandbox

import (
	"archive/tar"
	"encoding/binary"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/rwlayer"
	erofs "github.com/erofs/go-erofs"
)

func TestDefaultExportReferenceIsOCICompatible(t *testing.T) {
	for name, want := range map[string]string{
		"Dev.Name": "gantry-export/dev-name:latest",
		"a__B":     "gantry-export/a-b:latest",
		"---":      "gantry-export/sandbox:latest",
	} {
		if got := defaultExportReference(name); got != want {
			t.Errorf("defaultExportReference(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestExportSandboxProducesImportableStoppedSnapshot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GANTRY_HOME", filepath.Join(home, "sandboxes"))
	name := "share-dev"
	base := buildExportBaseImage(t)
	kernel := filepath.Join(home, "kernel")
	header := make([]byte, 0x40)
	binary.LittleEndian.PutUint32(header[0x38:], 0x644d5241)
	if err := os.WriteFile(kernel, header, 0o600); err != nil {
		t.Fatal(err)
	}
	layer, _, err := rwlayer.Default(name, "sha256:base", config.DefaultRWLayerSizeMiB, nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := layout.Dir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.RunConfig{
		Kernel: kernel, Image: base, ImageRef: "example/base:latest", ImageDigest: "sha256:base",
		ImageCfg: &image.Config{Env: []string{"EXPORTED=yes"}, WorkingDir: "/work"},
		RWLayer:  layer, RWLayerSizeMiB: config.DefaultRWLayerSizeMiB, RW: true, MemMB: 512, VCPUs: 1,
	}
	if err := config.WriteSandboxConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(home, "share-dev.oci.tar")
	busyLayer, err := os.OpenFile(layer, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gutil.TryLockFD(busyLayer); err != nil {
		t.Fatal(err)
	}
	if _, err := exportSandbox(name, output, "team/share-dev:v1", false, t.Logf); err == nil {
		t.Fatal("export accepted a writable layer locked by another process")
	}
	if err := busyLayer.Close(); err != nil {
		t.Fatal(err)
	}
	if status := CmdExport([]string{name, "-o", output, "--name", "team/share-dev:v1"}); status != 0 {
		t.Fatalf("CmdExport status = %d", status)
	}
	if info, err := os.Stat(output); err != nil || info.Size() == 0 {
		t.Fatalf("exported archive = %+v, %v", info, err)
	}

	store := image.NewStore(filepath.Join(home, "imported-images"))
	imported, err := image.ImportArchive(output, "", "arm64", store, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if imported.Ref != "team/share-dev:v1" || imported.Config == nil || imported.Config.WorkingDir != "/work" {
		t.Fatalf("imported = %+v", imported)
	}
	file, err := os.Open(imported.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	root, err := erofs.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	data, err := fs.ReadFile(root, "export-marker")
	if err != nil || string(data) != "base\n" {
		t.Fatalf("export-marker = %q, %v", data, err)
	}
}

func buildExportBaseImage(t *testing.T) string {
	t.Helper()
	layer, err := os.Create(filepath.Join(t.TempDir(), "base.tar"))
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(layer)
	body := []byte("base\n")
	if err := writer.WriteHeader(&tar.Header{Name: "export-marker", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := layer.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = layer.Close() }()
	base := filepath.Join(t.TempDir(), "base.erofs")
	if _, err := image.Build(base, []*os.File{layer}, nil, nil); err != nil {
		t.Fatal(err)
	}
	return base
}
