//go:build linux || darwin

package sandbox

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/erofs/go-erofs"
)

// buildFixtureImage renders a tiny EROFS image with the file shapes the
// extraction path must preserve: directories, a regular file, a symlink, and
// a setuid binary.
func buildFixtureImage(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.erofs")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := erofs.Create(f, erofs.WithBlockSize(4096))
	if err := w.Mkdir("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	release, err := w.Create("/etc/os-release")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.Write([]byte("NAME=gantry-fixture\n")); err != nil {
		t.Fatal(err)
	}
	if err := release.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Mkdir("/bin", 0o755); err != nil {
		t.Fatal(err)
	}
	sh, err := w.Create("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Write([]byte("#!/bin/sh\n")); err != nil {
		t.Fatal(err)
	}
	if err := sh.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Symlink("/bin/sh", "/bin/link-sh"); err != nil {
		t.Fatal(err)
	}
	su, err := w.Create("/bin/su")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := su.Write([]byte("su")); err != nil {
		t.Fatal(err)
	}
	if err := su.Close(); err != nil {
		t.Fatal(err)
	}
	// fs.FileMode represents setuid as fs.ModeSetuid, not the unix 0o4000 bit.
	if err := w.Chmod("/bin/su", 0o755|fs.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractImagePreservesSemantics(t *testing.T) {
	image := buildFixtureImage(t)
	snapshot := filepath.Join(t.TempDir(), "snapshot")
	if err := os.Mkdir(snapshot, 0o755); err != nil {
		t.Fatal(err)
	}
	prep := &rootfsSnapshotPrep{snapshot: snapshot}
	if err := prep.extractImage(image); err != nil {
		t.Fatalf("extractImage: %v", err)
	}

	release, err := os.ReadFile(filepath.Join(snapshot, "etc/os-release"))
	if err != nil || string(release) != "NAME=gantry-fixture\n" {
		t.Fatalf("os-release: %q, %v", release, err)
	}
	target, err := os.Readlink(filepath.Join(snapshot, "bin/link-sh"))
	if err != nil || target != "/bin/sh" {
		t.Fatalf("symlink: %q, %v", target, err)
	}
	info, err := os.Stat(filepath.Join(snapshot, "bin/su"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetuid == 0 {
		t.Errorf("setuid bit lost in extraction: mode %v", info.Mode())
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("perm bits lost in extraction: mode %v", info.Mode())
	}
}

func TestEnsureMountTargets(t *testing.T) {
	target := t.TempDir()
	if err := ensureMountTargets(target); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"proc", "dev/pts", "dev/shm", "dev/mqueue", "sys", "tmp"} {
		info, err := os.Stat(filepath.Join(target, dir))
		if err != nil || !info.IsDir() {
			t.Errorf("mount target %s missing: %v", dir, err)
		}
	}
	for _, file := range []string{"etc/hosts", "etc/resolv.conf"} {
		if info, err := os.Stat(filepath.Join(target, file)); err != nil || info.IsDir() {
			t.Errorf("mount target %s missing: %v", file, err)
		}
	}
	// Pre-existing content survives.
	hosts := filepath.Join(target, "etc/hosts")
	if err := os.WriteFile(hosts, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureMountTargets(target); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(hosts)
	if err != nil || string(content) != "127.0.0.1 localhost\n" {
		t.Errorf("existing /etc/hosts clobbered: %q", content)
	}
}

func TestPlaceSetuidCopySetsTheBit(t *testing.T) {
	target := t.TempDir()
	checker := filepath.Join(target, "spikecheck")
	if err := os.WriteFile(checker, []byte("payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := placeSetuidCopy(target, checker); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(target, "spike-setuid"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetuid == 0 {
		t.Errorf("setuid bit missing on the fixture: mode %v", info.Mode())
	}
}

func TestBuildCheckerPrebuiltOverride(t *testing.T) {
	prebuilt := filepath.Join(t.TempDir(), "prebuilt")
	if err := os.WriteFile(prebuilt, []byte("fake-linux-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GANTRY_SPIKECHECK_BIN", prebuilt)
	target := t.TempDir()
	p := &rootfsSnapshotPrep{}
	if err := p.buildChecker(target); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"spikecheck", "spike-setuid"} {
		payload, err := os.ReadFile(filepath.Join(target, name))
		if err != nil || string(payload) != "fake-linux-binary" {
			t.Errorf("%s = %q, %v", name, payload, err)
		}
	}
}
