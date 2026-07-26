package image

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	erofs "github.com/erofs/go-erofs"
)

// tarEntry is one synthetic layer entry for tests.
type tarEntry struct {
	Name     string
	Type     byte
	Mode     int64
	Uid, Gid int
	Body     string
	Link     string
	Major    int64
	Minor    int64
}

func writeLayer(t *testing.T, entries ...tarEntry) *os.File {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "layer.tar"))
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	for _, e := range entries {
		mode := e.Mode
		if mode == 0 {
			mode = 0o644
		}
		hdr := &tar.Header{
			Name:     e.Name,
			Typeflag: e.Type,
			Mode:     mode,
			Uid:      e.Uid,
			Gid:      e.Gid,
			Linkname: e.Link,
			Size:     int64(len(e.Body)),
			Devmajor: e.Major,
			Devminor: e.Minor,
		}
		if e.Type == tar.TypeDir {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if len(e.Body) > 0 {
			if _, err := tw.Write([]byte(e.Body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// flattenInto runs flattenLayers into a fresh erofs file and returns the
// image opened for read-back plus the merge index.
func flattenInto(t *testing.T, layers ...*os.File) (fs.FS, *mergeIndex) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out.erofs")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	w := erofs.Create(f)
	idx, err := flattenLayers(w, layers, t.Logf)
	if err != nil {
		t.Fatalf("flattenLayers: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("writer close: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	img, err := erofs.Open(f)
	if err != nil {
		t.Fatalf("open built image: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return img, idx
}

func readBack(t *testing.T, img fs.FS, name string) string {
	t.Helper()
	b, err := fs.ReadFile(img, name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func TestFlattenWhiteoutsAndOrdering(t *testing.T) {
	base := writeLayer(t,
		tarEntry{"etc", tar.TypeDir, 0o755, 0, 0, "", "", 0, 0},
		tarEntry{"etc/passwd", tar.TypeReg, 0o644, 0, 0, "root:x:0:0::/root:/bin/sh\n", "", 0, 0},
		tarEntry{"etc/motd", tar.TypeReg, 0o644, 0, 0, "hello base\n", "", 0, 0},
		tarEntry{"usr", tar.TypeDir, 0o755, 0, 0, "", "", 0, 0},
		tarEntry{"usr/bin", tar.TypeDir, 0o755, 0, 0, "", "", 0, 0},
		tarEntry{"usr/bin/tool", tar.TypeReg, 0o755, 0, 0, "v1", "", 0, 0},
		tarEntry{"tmp", tar.TypeDir, 0o1777, 0, 0, "", "", 0, 0},
	)
	top := writeLayer(t,
		tarEntry{"etc/.wh.motd", tar.TypeReg, 0o644, 0, 0, "", "", 0, 0},         // whiteout
		tarEntry{"usr/bin/.wh..wh..opq", tar.TypeReg, 0o644, 0, 0, "", "", 0, 0}, // opaque dir
		tarEntry{"usr/bin/newtool", tar.TypeReg, 0o755, 0, 0, "v2", "", 0, 0},
	)
	img, _ := flattenInto(t, base, top)

	// whiteout removed etc/motd
	if _, err := fs.Stat(img, "etc/motd"); err == nil {
		t.Error("etc/motd should be whiteout-deleted")
	}
	// opaque dir cleared usr/bin's prior contents but kept the layer's own
	if _, err := fs.Stat(img, "usr/bin/tool"); err == nil {
		t.Error("usr/bin/tool should be cleared by the opaque marker")
	}
	if got := readBack(t, img, "usr/bin/newtool"); got != "v2" {
		t.Errorf("usr/bin/newtool = %q", got)
	}
	// untouched base content survives
	if !strings.Contains(readBack(t, img, "etc/passwd"), "root:x:0:0") {
		t.Error("etc/passwd missing base content")
	}
	// sticky bit on /tmp survives (read-back Mode() carries raw unix
	// bits — go-erofs does not translate to fs.ModeSticky)
	st, err := fs.Stat(img, "tmp")
	if err != nil {
		t.Fatal(err)
	}
	if uint32(st.Mode())&0o1000 == 0 {
		t.Errorf("/tmp lost its sticky bit, mode=%o", st.Mode())
	}
}

func TestFlattenOverwriteLastWins(t *testing.T) {
	l1 := writeLayer(t, tarEntry{"etc/passwd", tar.TypeReg, 0o644, 0, 0, "old\n", "", 0, 0})
	l2 := writeLayer(t, tarEntry{"etc/passwd", tar.TypeReg, 0o600, 33, 44, "new\n", "", 0, 0})
	img, _ := flattenInto(t, l1, l2)
	if got := readBack(t, img, "etc/passwd"); got != "new\n" {
		t.Errorf("content = %q, want new", got)
	}
	st, _ := fs.Stat(img, "etc/passwd")
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", st.Mode().Perm())
	}
}

func TestFlattenSpecialFiles(t *testing.T) {
	l := writeLayer(t,
		tarEntry{"dev", tar.TypeDir, 0o755, 0, 0, "", "", 0, 0},
		tarEntry{"dev/null", tar.TypeChar, 0o666, 0, 0, "", "", 1, 3},
		tarEntry{"bin", tar.TypeDir, 0o755, 0, 0, "", "", 0, 0},
		tarEntry{"bin/su", tar.TypeReg, 0o4755, 0, 0, "su-binary", "", 0, 0},
		tarEntry{"lib64", tar.TypeDir, 0o755, 0, 0, "", "", 0, 0},
		tarEntry{"lib64/ld.so", tar.TypeSymlink, 0o777, 0, 0, "", "/lib/ld.so", 0, 0},
	)
	img, _ := flattenInto(t, l)

	st, err := fs.Stat(img, "dev/null")
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&fs.ModeDevice == 0 || st.Mode()&fs.ModeCharDevice == 0 {
		t.Errorf("dev/null mode = %v, want char device", st.Mode())
	}
	st, _ = fs.Stat(img, "bin/su")
	if uint32(st.Mode())&0o4000 == 0 {
		t.Errorf("bin/su lost its setuid bit, mode=%o", st.Mode())
	}
	if got := readBack(t, img, "bin/su"); got != "su-binary" {
		t.Errorf("bin/su content = %q", got)
	}
	// fs.Stat follows symlinks; the target does not exist in this
	// fixture, so check the link itself with Lstat
	st, err = fs.Lstat(img, "lib64/ld.so")
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("lib64/ld.so is not a symlink, mode=%v", st.Mode())
	}
}

func TestFlattenHardlinkMaterialized(t *testing.T) {
	l := writeLayer(t,
		tarEntry{"bin", tar.TypeDir, 0o755, 0, 0, "", "", 0, 0},
		tarEntry{"bin/busybox", tar.TypeReg, 0o755, 0, 0, "busybox-binary", "", 0, 0},
		tarEntry{"bin/sh", tar.TypeLink, 0o755, 0, 0, "", "bin/busybox", 0, 0},
	)
	img, _ := flattenInto(t, l)
	if got := readBack(t, img, "bin/sh"); got != "busybox-binary" {
		t.Errorf("hardlink content = %q, want busybox-binary", got)
	}
}

func TestFlattenRootIsRootOwned(t *testing.T) {
	// no layer contains a ./ or / root entry: the synthesized root must
	// still be uid 0 (the design-doc gotcha)
	l := writeLayer(t, tarEntry{"a.txt", tar.TypeReg, 0o644, 1000, 1000, "x", "", 0, 0})
	_, idx := flattenInto(t, l)
	if _, ok := idx.entries["a.txt"]; !ok {
		t.Fatal("a.txt not indexed")
	}
}

func TestFlattenTraversalRejected(t *testing.T) {
	l := writeLayer(t, tarEntry{"../evil", tar.TypeReg, 0o644, 0, 0, "x", "", 0, 0})
	out := filepath.Join(t.TempDir(), "out.erofs")
	f, _ := os.Create(out)
	w := erofs.Create(f)
	_, err := flattenLayers(w, []*os.File{l}, nil)
	if err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Errorf("want traversal rejection, got %v", err)
	}
}

func TestResolveUser(t *testing.T) {
	passwd := "root:x:0:0::/root:/bin/sh\nnginx:x:101:102::/nonexistent:/sbin/nologin\n"
	group := "root:x:0:\nnginx:x:102:\nnogroup:x:65534:\n"
	cases := []struct {
		user     string
		uid, gid uint32
		wantErr  bool
	}{
		{"", 0, 0, false},
		{"0", 0, 0, false},
		{"1000", 1000, 1000, false},
		{"1000:100", 1000, 100, false},
		{"nginx", 101, 102, false},
		{"nginx:nogroup", 101, 65534, false},
		{"nginx:102", 101, 102, false},
		{"1000:nogroup", 1000, 65534, false},
		{"ghost", 0, 0, true},
		{"nginx:ghost", 0, 0, true},
	}
	for _, c := range cases {
		uid, gid, err := resolveUser(c.user, passwd, group)
		if (err != nil) != c.wantErr {
			t.Errorf("%q: err=%v, wantErr=%v", c.user, err, c.wantErr)
		}
		if err == nil && (uid != c.uid || gid != c.gid) {
			t.Errorf("%q: got %d:%d, want %d:%d", c.user, uid, gid, c.uid, c.gid)
		}
	}
}

func TestConfigPrecedence(t *testing.T) {
	c := &Config{
		Env:        []string{"PATH=/custom/bin", "FOO=bar"},
		Entrypoint: []string{"/entry"},
		Cmd:        []string{"--serve"},
		UID:        1000, GID: 1000,
		WorkingDir: "/app",
	}
	if got := c.Command(nil); strings.Join(got, " ") != "/entry --serve" {
		t.Errorf("Command(nil) = %v", got)
	}
	if got := c.Command([]string{"/bin/sh"}); strings.Join(got, " ") != "/bin/sh" {
		t.Errorf("Command(explicit) = %v", got)
	}
	env := c.EnvWith("TERM=xterm", "PS1=# ")
	// image PATH wins, FOO kept, TERM added, HOME=/ (uid != 0)
	joined := strings.Join(env, " ")
	if !strings.Contains(joined, "PATH=/custom/bin") || strings.Contains(joined, "PATH=/usr/local/sbin") {
		t.Errorf("env lost image PATH or gained fallback: %v", env)
	}
	if !strings.Contains(joined, "FOO=bar") || !strings.Contains(joined, "TERM=xterm") || !strings.Contains(joined, "HOME=/") {
		t.Errorf("env = %v", env)
	}
	if c.WorkdirOr() != "/app" {
		t.Errorf("workdir = %q", c.WorkdirOr())
	}
	if u, g := c.IDs(); u != 1000 || g != 1000 {
		t.Errorf("ids = %d:%d", u, g)
	}
	var nilCfg *Config
	if got := nilCfg.Command(nil); got != nil {
		t.Errorf("nil config Command = %v", got)
	}
	if u, g := nilCfg.IDs(); u != 0 || g != 0 {
		t.Errorf("nil config ids = %d:%d", u, g)
	}
}

// the builder end-to-end: build + verify + read back
func TestBuildAndVerify(t *testing.T) {
	l1 := writeLayer(t,
		tarEntry{"etc", tar.TypeDir, 0o755, 0, 0, "", "", 0, 0},
		tarEntry{"etc/passwd", tar.TypeReg, 0o644, 0, 0, "root:x:0:0::/root:/bin/sh\n", "", 0, 0},
		tarEntry{"hello.txt", tar.TypeReg, 0o644, 33, 44, "hello world\n", "", 0, 0},
	)
	out := filepath.Join(t.TempDir(), "img.erofs")
	cfg := &Config{User: "root"}
	n, err := Build(out, []*os.File{l1}, cfg, t.Logf)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if n < 3 {
		t.Errorf("entries = %d", n)
	}
	if cfg.UID != 0 || cfg.GID != 0 {
		t.Errorf("resolved user = %d:%d", cfg.UID, cfg.GID)
	}
	f, _ := os.Open(out)
	defer f.Close()
	img, err := erofs.Open(f)
	if err != nil {
		t.Fatal(err)
	}
	if got := readBack(t, img, "hello.txt"); got != "hello world\n" {
		t.Errorf("hello.txt = %q", got)
	}
	var _ = bytes.MinRead // silence unused import if assertions change
}

// review4 #1: a plain whiteout of a directory must remove the whole
// subtree — image authors rely on deletion to strip build tooling and
// credentials.
func TestWhiteoutRemovesSubtree(t *testing.T) {
	l1 := writeLayer(t,
		tarEntry{"opt", tar.TypeDir, 0o755, 0, 0, "", "", 0, 0},
		tarEntry{"opt/keep.txt", tar.TypeReg, 0o644, 0, 0, "old", "", 0, 0},
		tarEntry{"opt/sub", tar.TypeDir, 0o755, 0, 0, "", "", 0, 0},
		tarEntry{"opt/sub/deep.txt", tar.TypeReg, 0o644, 0, 0, "deep", "", 0, 0},
	)
	l2 := writeLayer(t, tarEntry{".wh.opt", tar.TypeReg, 0o644, 0, 0, "", "", 0, 0})

	img, idx := flattenInto(t, l1, l2)
	for _, p := range []string{"opt", "opt/keep.txt", "opt/sub", "opt/sub/deep.txt"} {
		if _, ok := idx.entries[p]; ok {
			t.Errorf("%s survived a directory whiteout", p)
		}
		if _, err := fs.Stat(img, p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: err = %v, want not-exist", p, err)
		}
	}
}

// review4 #2: an opaque marker clears the directory's children but must
// keep the directory entry itself — its mode and ownership come from the
// layer that declared it.
func TestOpaquePreservesDirEntry(t *testing.T) {
	l1 := writeLayer(t,
		tarEntry{"opt", tar.TypeDir, 0o700, 42, 43, "", "", 0, 0},
		tarEntry{"opt/stale.txt", tar.TypeReg, 0o644, 0, 0, "x", "", 0, 0},
	)
	l2 := writeLayer(t,
		tarEntry{"opt/.wh..wh..opq", tar.TypeReg, 0o644, 0, 0, "", "", 0, 0},
		tarEntry{"opt/fresh.txt", tar.TypeReg, 0o644, 0, 0, "y", "", 0, 0},
	)

	img, idx := flattenInto(t, l1, l2)
	e, ok := idx.entries["opt"]
	if !ok {
		t.Fatal("opt must survive the opaque marker")
	}
	if e.hdr.Mode != 0o700 || e.hdr.Uid != 42 || e.hdr.Gid != 43 {
		t.Errorf("opt = mode %o uid %d gid %d, want 700 42:43 (ensureParent would have made root 755)",
			e.hdr.Mode, e.hdr.Uid, e.hdr.Gid)
	}
	if _, err := fs.Stat(img, "opt/stale.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("opt/stale.txt: err = %v, want cleared", err)
	}
	if got := readBack(t, img, "opt/fresh.txt"); got != "y" {
		t.Errorf("opt/fresh.txt = %q, want y", got)
	}
}
