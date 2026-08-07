package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	erofs "github.com/erofs/go-erofs"
)

// ociFixture builds a minimal OCI layout: one config blob, one gzipped
// layer tar, a manifest, and index.json — digests computed for real.
func ociFixture(t *testing.T, arch string, layerEntries []tarEntry, cfgJSON string) string {
	t.Helper()
	dir := t.TempDir()
	blobs := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobs, 0o755); err != nil {
		t.Fatal(err)
	}
	putBlob := func(b []byte) string {
		sum := sha256.Sum256(b)
		p := filepath.Join(blobs, fmt.Sprintf("%x", sum))
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("sha256:%x", sum)
	}

	// layer tar, gzipped (as registries store it)
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	for _, e := range layerEntries {
		mode := e.Mode
		if mode == 0 {
			mode = 0o644
		}
		hdr := &tar.Header{Name: e.Name, Typeflag: e.Type, Mode: mode,
			Uid: e.Uid, Gid: e.Gid, Linkname: e.Link, Size: int64(len(e.Body))}
		if e.Type == tar.TypeDir {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.Body != "" {
			_, _ = tw.Write([]byte(e.Body))
		}
	}
	_ = tw.Close()
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, _ = gw.Write(tb.Bytes())
	_ = gw.Close()
	layerDigest := putBlob(gz.Bytes())

	if cfgJSON == "" {
		cfgJSON = fmt.Sprintf(`{"architecture":%q,"os":"linux","config":{
			"Env":["PATH=/usr/bin","APP_HOME=/srv"],
			"Entrypoint":["/entry"],"Cmd":["run"],
			"User":"app","WorkingDir":"/srv"}}`, arch)
	}
	cfgDigest := putBlob([]byte(cfgJSON))

	manifest := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
		"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},
		"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":%q,"size":%d}]}`,
		cfgDigest, len(cfgJSON), layerDigest, gz.Len())
	manDigest := putBlob([]byte(manifest))

	index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json",
		"digest":%q,"size":%d,"platform":{"architecture":%q,"os":"linux"}}]}`,
		manDigest, len(manifest), arch)
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(index), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestResolveOCILayoutEndToEnd(t *testing.T) {
	layout := ociFixture(t, "arm64", []tarEntry{
		{"etc", tar.TypeDir, 0o755, 0, 0, "", "", 0, 0},
		{"etc/passwd", tar.TypeReg, 0o644, 0, 0, "root:x:0:0::/root:/bin/sh\napp:x:1000:1000::/srv:/bin/sh\n", "", 0, 0},
		{"srv", tar.TypeDir, 0o755, 1000, 1000, "", "", 0, 0},
		{"entry", tar.TypeReg, 0o755, 0, 0, "#!/bin/sh\necho hi\n", "", 0, 0},
	}, "")

	st := NewStore(t.TempDir())
	r, err := Resolve(layout, "arm64", st, t.Logf)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Digest == "" || r.Path == "" || r.Config == nil {
		t.Fatalf("incomplete resolve: %+v", r)
	}
	// config: user resolved against the merged passwd at build time
	if r.Config.UID != 1000 || r.Config.GID != 1000 {
		t.Errorf("user resolved to %d:%d, want 1000:1000", r.Config.UID, r.Config.GID)
	}
	if r.Config.WorkingDir != "/srv" || len(r.Config.Entrypoint) != 1 {
		t.Errorf("config = %+v", r.Config)
	}

	// the cached image reads back
	f, err := os.Open(r.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	img, err := erofs.Open(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := readAllFile(img, "entry")
	if err != nil || string(b) != "#!/bin/sh\necho hi\n" {
		t.Errorf("entry content = %q, %v", b, err)
	}

	// second resolve hits the cache (same digest, no rebuild)
	r2, err := Resolve(layout, "arm64", st, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Digest != r.Digest || r2.Path != r.Path {
		t.Errorf("cache miss on identical layout: %+v", r2)
	}

	// arch mismatch is a CLI-time error, not an exec format error in the VM
	if _, err := Resolve(layout, "amd64", NewStore(t.TempDir()), nil); err == nil {
		t.Error("want platform mismatch error for amd64 guest")
	}
}

func TestResolveDockerSave(t *testing.T) {
	// minimal docker save tar: manifest.json + config + one layer.tar
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name string, b []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(b))}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write(b)
	}
	var lb bytes.Buffer
	lw := tar.NewWriter(&lb)
	_ = lw.WriteHeader(&tar.Header{Name: "hello.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5})
	_, _ = lw.Write([]byte("hello"))
	_ = lw.Close()
	add("aaa111/layer.tar", lb.Bytes())
	cfg := `{"architecture":"amd64","os":"linux","config":{"Cmd":["/bin/app"],"User":""}}`
	add("ccc333.json", []byte(cfg))
	man := `[{"Config":"ccc333.json","RepoTags":["app:latest"],"Layers":["aaa111/layer.tar"]}]`
	add("manifest.json", []byte(man))
	_ = tw.Close()

	savePath := filepath.Join(t.TempDir(), "save.tar")
	if err := os.WriteFile(savePath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	st := NewStore(t.TempDir())
	r, err := Resolve(savePath, "amd64", st, t.Logf)
	if err != nil {
		t.Fatalf("Resolve docker save: %v", err)
	}
	if r.Config == nil || len(r.Config.Cmd) != 1 || r.Config.Cmd[0] != "/bin/app" {
		t.Errorf("config = %+v", r.Config)
	}
	f, _ := os.Open(r.Path)
	defer func() { _ = f.Close() }()
	img, err := erofs.Open(f)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := readAllFile(img, "hello.txt"); err != nil || string(b) != "hello" {
		t.Errorf("hello.txt = %q, %v", b, err)
	}
}

func readAllFile(fsys fs.FS, name string) ([]byte, error) {
	return fs.ReadFile(fsys, name)
}

// An explicit path that doesn't exist must produce a clear "not found",
// never a registry pull from a mangled hostname ("./pi-agent.tar" used
// to become a pull from a registry literally named ".").
func TestResolveMissingPathIsClearError(t *testing.T) {
	for _, ref := range []string{"./pi-agent.tar", "/tmp/nope.tar", "~/x.oci", "images/foo.tar"} {
		_, err := Resolve(ref, "arm64", NewStore(t.TempDir()), nil)
		if err == nil || !strings.Contains(err.Error(), "image file not found") {
			t.Errorf("Resolve(%q): err = %v, want image-file-not-found", ref, err)
		}
	}
}

// docker save tars from podman / older docker name layers <digest>.tar
// at the top level; containerd-backed docker uses OCI-style
// blobs/sha256/<digest> with no suffix. Both must resolve — the loader
// used to accept only <id>/layer.tar and reject these with
// "is not in the tar".
func TestResolveDockerSaveNamingVariants(t *testing.T) {
	layerTar := func(content string) []byte {
		var lb bytes.Buffer
		lw := tar.NewWriter(&lb)
		_ = lw.WriteHeader(&tar.Header{Name: "hello.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))})
		_, _ = lw.Write([]byte(content))
		_ = lw.Close()
		return lb.Bytes()
	}
	cfg := `{"architecture":"amd64","os":"linux","config":{"Cmd":["/bin/app"]}}`

	for _, tc := range []struct {
		name    string
		members map[string][]byte // member name -> content (manifest.json added by the test)
		cfgName string
		layer   string
	}{
		{
			name: "podman top-level <digest>.tar",
			members: map[string][]byte{
				"12cdff3b.tar": layerTar("hello"),
				"ab90.json":    []byte(cfg),
			},
			cfgName: "ab90.json",
			layer:   "12cdff3b.tar",
		},
		{
			name: "containerd blobs/sha256/<digest>",
			members: map[string][]byte{
				"blobs/sha256/1111": layerTar("hello"),
				"blobs/sha256/2222": []byte(cfg),
			},
			cfgName: "blobs/sha256/2222",
			layer:   "blobs/sha256/1111",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			for name, b := range tc.members {
				if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(b))}); err != nil {
					t.Fatal(err)
				}
				_, _ = tw.Write(b)
			}
			man := fmt.Sprintf(`[{"Config":%q,"RepoTags":["app:latest"],"Layers":[%q]}]`, tc.cfgName, tc.layer)
			_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(man))})
			_, _ = tw.Write([]byte(man))
			_ = tw.Close()

			savePath := filepath.Join(t.TempDir(), "save.tar")
			if err := os.WriteFile(savePath, buf.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
			r, err := Resolve(savePath, "amd64", NewStore(t.TempDir()), t.Logf)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if r.Config == nil || len(r.Config.Cmd) != 1 || r.Config.Cmd[0] != "/bin/app" {
				t.Errorf("config = %+v", r.Config)
			}
			f, _ := os.Open(r.Path)
			defer func() { _ = f.Close() }()
			img, err := erofs.Open(f)
			if err != nil {
				t.Fatal(err)
			}
			if b, err := readAllFile(img, "hello.txt"); err != nil || string(b) != "hello" {
				t.Errorf("hello.txt = %q, %v", b, err)
			}
		})
	}
}
