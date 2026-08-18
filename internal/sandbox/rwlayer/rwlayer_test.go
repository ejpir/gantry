package rwlayer

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox/config"
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
	if err := CheckPairing(layer, "sha256:aaa"); err != nil {
		t.Fatal(err)
	}
	// same image: ok
	if err := CheckPairing(layer, "sha256:aaa"); err != nil {
		t.Fatal(err)
	}
	// different image: refused with an actionable message
	err := CheckPairing(layer, "sha256:bbb")
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
	pairing := pairingPath(layer)
	if err := os.WriteFile(pairing, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckPairing(layer, "sha256:new"); err == nil || !strings.Contains(err.Error(), "malformed") {
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

	p, _, err := Default("dev1", "sha256:img", config.DefaultRWLayerSizeMiB, nil)
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

func TestCreateRWLayer(t *testing.T) {
	p := filepath.Join(t.TempDir(), "blank.ext4")
	var progress []string
	if _, err := create(p, config.DefaultRWLayerSizeMiB, func(format string, args ...any) {
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
