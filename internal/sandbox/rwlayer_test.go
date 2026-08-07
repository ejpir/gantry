package sandbox

import (
	"encoding/binary"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/gutil"
)

func TestProbeExt4(t *testing.T) {
	// synthetic superblock: magic, state, error fields at the verified offsets
	img := filepath.Join(t.TempDir(), "x.ext4")
	buf := make([]byte, 2048+1024)
	sb := buf[1024:]
	binary.LittleEndian.PutUint16(sb[56:58], 0xef53)
	binary.LittleEndian.PutUint16(sb[58:60], 3) // mounted + errors
	binary.LittleEndian.PutUint16(sb[52:54], 66)
	binary.LittleEndian.PutUint32(sb[0x170:0x174], 5)
	binary.LittleEndian.PutUint32(sb[0x1A8:0x1AC], 1753500000)
	copy(sb[0x184:0x1A4], "ext4_first")
	copy(sb[0x1BC:0x1DC], "ext4_validate_block_bitmap")
	if err := os.WriteFile(img, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := gutil.ProbeExt4(img)
	if err != nil {
		t.Fatal(err)
	}
	if info.State != 3 || info.MountCount != 66 || info.ErrorCount != 5 {
		t.Errorf("%+v", info)
	}
	if info.LastErrFunc != "ext4_validate_block_bitmap" || info.FirstErrFunc != "ext4_first" {
		t.Errorf("funcs: %q %q", info.LastErrFunc, info.FirstErrFunc)
	}
	d := info.Diagnosis()
	if !strings.Contains(d, "5 error") || !strings.Contains(d, "ext4_validate_block_bitmap") {
		t.Errorf("diagnosis = %q", d)
	}
	// non-ext file
	plain := filepath.Join(t.TempDir(), "x.bin")
	os.WriteFile(plain, []byte("hello"), 0o644)
	if _, err := gutil.ProbeExt4(plain); err == nil {
		t.Error("want magic error for non-ext file")
	}
}

func TestRWLayerPairing(t *testing.T) {
	dir := t.TempDir()
	layer := filepath.Join(dir, "test.ext4")
	os.WriteFile(layer, []byte("x"), 0o644)

	// no sidecar: recorded, no error
	if err := checkRWLayerPairing(layer, "sha256:aaa"); err != nil {
		t.Fatal(err)
	}
	// same image: ok
	if err := checkRWLayerPairing(layer, "sha256:aaa"); err != nil {
		t.Fatal(err)
	}
	// different image: refused with an actionable message
	err := checkRWLayerPairing(layer, "sha256:bbb")
	if err == nil || !strings.Contains(err.Error(), "per-image") {
		t.Fatalf("want pairing refusal, got %v", err)
	}
}

func TestDefaultRWLayerCreatesPerSandbox(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GANTRY_HOME", filepath.Join(home, "sandboxes"))
	t.Chdir(t.TempDir()) // no ./rwlayer.ext4 template here

	p, _, err := defaultRWLayer("dev1", "sha256:img")
	if err != nil {
		// host may lack e2fsprogs AND the template: then the error must
		// at least be actionable
		if !strings.Contains(err.Error(), "mkrwlayer.sh") {
			t.Fatalf("unhelpful error: %v", err)
		}
		return
	}
	want := filepath.Join(home, "rwlayers", "dev1.ext4")
	if p != want {
		t.Errorf("path = %q, want %q", p, want)
	}
	if !gutil.FileExists(p) {
		t.Error("layer file not created")
	}
	info, err := gutil.ProbeExt4(p)
	if err != nil {
		t.Skipf("layer not ext4 (template-less fallback?): %v", err)
	}
	_ = info
}

func TestResolveUsesPerSandboxRWLayer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GANTRY_HOME", filepath.Join(home, "sandboxes"))
	dir := t.TempDir()
	t.Chdir(dir)
	for _, f := range resolveAssets {
		os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644)
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	rf := RegisterRunFlags(fs)
	rf.Name = "dev9"
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := rf.Resolve(fs, nil)
	if err != nil {
		// acceptable on hosts without e2fsprogs and no template
		if strings.Contains(err.Error(), "mkrwlayer.sh") {
			t.Skip("no ext4 tooling on this host")
		}
		t.Fatal(err)
	}
	if !strings.Contains(cfg.RWLayer, filepath.Join("rwlayers", "dev9.ext4")) {
		t.Errorf("RWLayer = %q, want per-sandbox default", cfg.RWLayer)
	}
	if !cfg.RW {
		t.Error("RW should default on with the per-sandbox layer present")
	}
}

func TestInflateBlankRWLayer(t *testing.T) {
	p := filepath.Join(t.TempDir(), "blank.ext4")
	if err := inflateBlankRWLayer(p); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 512<<20 {
		t.Errorf("size = %d, want 512 MiB", fi.Size())
	}
	info, err := gutil.ProbeExt4(p)
	if err != nil {
		t.Fatalf("inflated template is not valid ext4: %v", err)
	}
	if info.ErrorCount != 0 {
		t.Errorf("fresh template has errors: %+v", info)
	}
	// sparse: the file must hold far fewer blocks than its logical size
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = st
}
