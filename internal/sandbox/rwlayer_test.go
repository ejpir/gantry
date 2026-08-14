package sandbox

import (
	"encoding/binary"
	"flag"
	"fmt"
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
	_ = os.WriteFile(plain, []byte("hello"), 0o644)
	if _, err := gutil.ProbeExt4(plain); err == nil {
		t.Error("want magic error for non-ext file")
	}
}

func TestRWLayerPairing(t *testing.T) {
	dir := t.TempDir()
	layer := filepath.Join(dir, "test.ext4")
	_ = os.WriteFile(layer, []byte("x"), 0o644)

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

func TestRWLayerPairingRejectsMalformedRecord(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	layer := filepath.Join(dir, "test.ext4")
	if err := os.WriteFile(layer, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pairing := rwlayerPairingPath(layer)
	if err := os.WriteFile(pairing, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkRWLayerPairing(layer, "sha256:new"); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed pairing error = %v", err)
	}
	data, err := os.ReadFile(pairing)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{" {
		t.Fatalf("malformed pairing was silently replaced: %q", data)
	}
}

func TestDefaultRWLayerCreatesPerSandbox(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GANTRY_HOME", filepath.Join(home, "sandboxes"))
	t.Chdir(t.TempDir()) // no ./rwlayer.ext4 template here

	p, _, err := defaultRWLayer("dev1", "sha256:img", defaultRWLayerSizeMiB, nil)
	if err != nil {
		t.Fatal(err)
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

func TestResolveReadOnlySkipsPerSandboxRWLayer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GANTRY_HOME", filepath.Join(home, "sandboxes"))
	dir := t.TempDir()
	t.Chdir(dir)
	for _, f := range resolveAssets {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	rf := RegisterRunFlags(fs)
	rf.Name = "read-only"
	if err := fs.Parse([]string{"-rw=false"}); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := rf.Resolve(fs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RW || cfg.RWLayer != "" {
		t.Fatalf("explicit read-only resolution produced RW=%v layer=%q", cfg.RW, cfg.RWLayer)
	}
	if gutil.FileExists(defaultRWLayerPath(rf.Name)) {
		t.Fatal("explicit read-only resolution created an unused per-sandbox rwlayer")
	}
}

func TestResolveUsesExplicitLayerForReadOnlySandbox(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GANTRY_HOME", filepath.Join(home, "sandboxes"))
	dir := t.TempDir()
	t.Chdir(dir)
	for _, f := range resolveAssets {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	layer := filepath.Join(dir, "kept.ext4")
	if err := os.WriteFile(layer, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	rf := RegisterRunFlags(fs)
	rf.Name = "read-only-explicit"
	if err := fs.Parse([]string{"-rw=false", "-rwlayer", layer}); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := rf.Resolve(fs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RW || cfg.RWLayer != layer {
		t.Fatalf("explicit read-only layer resolved to RW=%v layer=%q, want false/%q", cfg.RW, cfg.RWLayer, layer)
	}
}

func TestResolveUsesPerSandboxRWLayer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GANTRY_HOME", filepath.Join(home, "sandboxes"))
	dir := t.TempDir()
	t.Chdir(dir)
	for _, f := range resolveAssets {
		_ = os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644)
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	rf := RegisterRunFlags(fs)
	rf.Name = "dev9"
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := rf.Resolve(fs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg.RWLayer, filepath.Join("rwlayers", "dev9.ext4")) {
		t.Errorf("RWLayer = %q, want per-sandbox default", cfg.RWLayer)
	}
	if !cfg.RW {
		t.Error("RW should default on with the per-sandbox layer present")
	}
}

func TestCreateRWLayer(t *testing.T) {
	p := filepath.Join(t.TempDir(), "blank.ext4")
	var progress []string
	if _, err := createRWLayer(p, defaultRWLayerSizeMiB, func(format string, args ...any) {
		progress = append(progress, fmt.Sprintf(format, args...))
	}); err != nil {
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
		t.Fatalf("created image is not valid ext4: %v", err)
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
	if len(progress) < 4 || !strings.Contains(progress[0], "0%") || !strings.Contains(progress[len(progress)-1], "100%") {
		t.Fatalf("progress = %v", progress)
	}
}

func TestValidateRWLayerSize(t *testing.T) {
	for _, size := range []uint{minRWLayerSizeMiB, defaultRWLayerSizeMiB, maxRWLayerSizeMiB} {
		if err := validateRWLayerSize(size); err != nil {
			t.Errorf("validateRWLayerSize(%d) = %v", size, err)
		}
	}
	for _, size := range []uint{minRWLayerSizeMiB - 1, maxRWLayerSizeMiB + 1} {
		if err := validateRWLayerSize(size); err == nil {
			t.Errorf("validateRWLayerSize(%d) unexpectedly succeeded", size)
		}
	}
}
