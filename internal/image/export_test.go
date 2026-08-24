package image

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	backendfile "github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/ext4"
	erofs "github.com/erofs/go-erofs"
)

func TestExportOCIRoundTripIncludesPersistentUpper(t *testing.T) {
	baseLayer := writeLayer(t,
		tarEntry{Name: "etc", Type: tar.TypeDir, Mode: 0o755},
		tarEntry{Name: "etc/base", Type: tar.TypeReg, Mode: 0o644, Body: "old\n"},
		tarEntry{Name: "remove-me", Type: tar.TypeReg, Mode: 0o644, Body: "remove\n"},
		tarEntry{Name: "bin", Type: tar.TypeDir, Mode: 0o755},
		tarEntry{Name: "bin/tool", Type: tar.TypeReg, Mode: 0o755, Body: "tool\n"},
		tarEntry{Name: "bin/sh", Type: tar.TypeSymlink, Mode: 0o777, Link: "tool"},
	)
	basePath := filepath.Join(t.TempDir(), "base.erofs")
	baseConfig := &Config{
		Env: []string{"A=B"}, Entrypoint: []string{"/bin/tool"}, Cmd: []string{"serve"},
		User: "1000:1001", WorkingDir: "/workspace",
	}
	if _, err := Build(basePath, []*os.File{baseLayer}, baseConfig, t.Logf); err != nil {
		t.Fatal(err)
	}
	rwLayerPath := createExportUpper(t)
	rwLayer, err := os.Open(rwLayerPath)
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "sandbox.oci.tar")
	created := time.Unix(1_700_000_000, 0).UTC()
	result, err := ExportOCI(ExportOptions{
		Output: archive, Reference: "gantry-export/dev:latest", Architecture: "amd64",
		Base: basePath, RWLayer: rwLayer, Config: baseConfig, Created: created,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reference != "gantry-export/dev:latest" || !strings.HasPrefix(result.ManifestDigest, "sha256:") {
		t.Fatalf("result = %+v", result)
	}
	if info, err := os.Stat(archive); err != nil || info.Size() == 0 {
		t.Fatalf("archive stat = %+v, %v", info, err)
	} else if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("archive mode = %o, want private", info.Mode().Perm())
	}
	assertOCIArchiveShape(t, archive, "gantry-export/dev:latest", 2)

	store := NewStore(filepath.Join(t.TempDir(), "images"))
	direct, err := Resolve(archive, "amd64", store, t.Logf)
	if err != nil || direct.Ref != archive {
		t.Fatalf("direct OCI archive resolve = %+v, %v", direct, err)
	}
	resolved, err := ImportArchive(archive, "", "amd64", store, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Ref != "gantry-export/dev:latest" || !resolved.Cached {
		t.Fatalf("imported alias = %+v; want embedded ref and existing content reuse", resolved)
	}
	if resolved.Config == nil || resolved.Config.WorkingDir != "/workspace" || resolved.Config.User != "1000:1001" ||
		resolved.Config.UID != 1000 || resolved.Config.GID != 1001 || len(resolved.Config.Env) != 1 || resolved.Config.Env[0] != "A=B" {
		t.Fatalf("imported config = %+v", resolved.Config)
	}
	imageFile, err := os.Open(resolved.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = imageFile.Close() }()
	root, err := erofs.Open(imageFile)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"etc/base":  "new\n",
		"etc/added": "added\n",
		"bin/tool":  "tool\n",
	} {
		got, err := fs.ReadFile(root, name)
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	addedInfo, err := fs.Stat(root, "etc/added")
	if err != nil {
		t.Fatal(err)
	}
	ownership, ok := addedInfo.(interface {
		UID() uint32
		GID() uint32
	})
	if !ok || ownership.UID() != 123 || ownership.GID() != 456 || addedInfo.Mode().Perm() != 0o600 {
		t.Errorf("etc/added metadata = mode %o, ownership %+v", addedInfo.Mode().Perm(), ownership)
	}
	linkFS, ok := root.(interface{ ReadLink(string) (string, error) })
	if !ok {
		t.Fatal("imported EROFS has no ReadLink")
	}
	if target, err := linkFS.ReadLink("tool-link"); err != nil || target != "bin/tool" {
		t.Errorf("tool-link = %q, %v", target, err)
	}
	if target, err := linkFS.ReadLink("bin/sh"); err != nil || target != "tool" {
		t.Errorf("bin/sh = %q, %v", target, err)
	}
	if err := os.Remove(archive); err != nil {
		t.Fatal(err)
	}
	if cached, err := ResolvePreferCached("gantry-export/dev:latest", "amd64", store, nil); err != nil || cached == nil {
		t.Fatalf("imported local reference is not reusable after removing the archive: %+v, %v", cached, err)
	}
}

func TestExportOCIRefusesOverwriteUnlessForced(t *testing.T) {
	layer := writeLayer(t, tarEntry{Name: "file", Type: tar.TypeReg, Body: "base"})
	base := filepath.Join(t.TempDir(), "base.erofs")
	if _, err := Build(base, []*os.File{layer}, nil, nil); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "out.oci.tar")
	if err := os.WriteFile(output, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := ExportOptions{Output: output, Reference: "example/export:latest", Architecture: "amd64", Base: base}
	if _, err := ExportOCI(options); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrite error = %v", err)
	}
	if data, _ := os.ReadFile(output); string(data) != "keep" {
		t.Fatalf("refused overwrite changed output to %q", data)
	}
	options.Force = true
	if _, err := ExportOCI(options); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(output); string(data) == "keep" {
		t.Fatal("forced export did not replace output")
	}
}

func TestOverlayWhiteoutConversion(t *testing.T) {
	name, ok := overlayWhiteoutName("etc/removed", fs.ModeDevice|fs.ModeCharDevice, 0, 0)
	if !ok || name != "etc/.wh.removed" {
		t.Fatalf("whiteout = %q, %v", name, ok)
	}
	for _, test := range []struct {
		mode         fs.FileMode
		major, minor uint32
	}{
		{fs.ModeDevice, 0, 0},
		{fs.ModeDevice | fs.ModeCharDevice, 1, 0},
		{fs.ModeDevice | fs.ModeCharDevice, 0, 1},
		{0, 0, 0},
	} {
		if name, ok := overlayWhiteoutName("node", test.mode, test.major, test.minor); ok {
			t.Errorf("non-whiteout converted to %q for %+v", name, test)
		}
	}
}

func TestOverlayAttributesRejectRedirectAndRemovePrivateMetadata(t *testing.T) {
	attributes := map[string][]byte{
		"trusted.overlay.opaque": []byte("y"),
		"trusted.overlay.origin": []byte("private-handle"),
		"user.keep":              []byte("value"),
	}
	opaque, err := overlayAttributes(attributes)
	if err != nil || !opaque {
		t.Fatalf("opaque = %v, err = %v", opaque, err)
	}
	if _, ok := attributes["trusted.overlay.opaque"]; ok {
		t.Fatal("opaque implementation xattr survived")
	}
	if _, ok := attributes["trusted.overlay.origin"]; ok {
		t.Fatal("origin implementation xattr survived")
	}
	if string(attributes["user.keep"]) != "value" {
		t.Fatal("ordinary xattr was removed")
	}
	if _, err := overlayAttributes(map[string][]byte{"trusted.overlay.redirect": []byte("old")}); err == nil {
		t.Fatal("redirect metadata was accepted")
	}
}

func createExportUpper(t *testing.T) string {
	t.Helper()
	const size = int64(64 << 20)
	path := filepath.Join(t.TempDir(), "upper.ext4")
	storage, err := backendfile.CreateFromPath(path, size)
	if err != nil {
		t.Fatal(err)
	}
	filesystem, err := ext4.Create(storage, size, 0, 512, &ext4.Params{VolumeName: "export-test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"upper", "upper/etc", "work"} {
		if err := filesystem.Mkdir(directory); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, content string, mode fs.FileMode) {
		file, err := filesystem.OpenFile(name, os.O_CREATE|os.O_RDWR)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := filesystem.Chmod(name, mode); err != nil {
			t.Fatal(err)
		}
	}
	write("upper/etc/base", "new\n", 0o640)
	write("upper/etc/added", "added\n", 0o600)
	if err := filesystem.Chown("upper/etc/added", 123, 456); err != nil {
		t.Fatal(err)
	}
	if err := filesystem.Symlink("bin/tool", "upper/tool-link"); err != nil {
		t.Fatal(err)
	}
	if err := filesystem.Close(); err != nil {
		t.Fatal(err)
	}
	if file, err := storage.Sys(); err == nil {
		if err := file.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertOCIArchiveShape(t *testing.T, archive, reference string, layerCount int) {
	t.Helper()
	file, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	reader := tar.NewReader(file)
	members := map[string][]byte{}
	for {
		header, err := reader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		data := make([]byte, header.Size)
		if _, err := io.ReadFull(reader, data); err != nil {
			t.Fatal(err)
		}
		members[header.Name] = data
	}
	if _, ok := members["oci-layout"]; !ok {
		t.Fatal("archive has no oci-layout")
	}
	var index struct {
		Manifests []descriptor `json:"manifests"`
	}
	if err := json.Unmarshal(members["index.json"], &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Manifests) != 1 || index.Manifests[0].Annotations[ociRefNameAnnotation] != reference {
		t.Fatalf("index manifests = %+v", index.Manifests)
	}
	var manifest struct {
		Layers []descriptor `json:"layers"`
	}
	if err := json.Unmarshal(members[blobName(index.Manifests[0].Digest)], &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Layers) != layerCount {
		t.Fatalf("layer count = %d, want %d", len(manifest.Layers), layerCount)
	}
}
