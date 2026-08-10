package guestasset

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultKernelPreference(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GANTRY_ARTIFACTS", dir)
	gantry, nerdbox := kernelNames(runtime.GOARCH)

	if got := DefaultKernel(); filepath.Base(got) != gantry {
		t.Errorf("empty artifacts: got %s, want .../%s", got, gantry)
	}
	if err := os.WriteFile(filepath.Join(dir, nerdbox), []byte("stock"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DefaultKernel(); filepath.Base(got) != nerdbox {
		t.Errorf("stock kernel staged: got %s, want .../%s", got, nerdbox)
	}
	if err := os.WriteFile(filepath.Join(dir, gantry), []byte("hardened"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DefaultKernel(); filepath.Base(got) != gantry {
		t.Errorf("both staged: got %s, want .../%s", got, gantry)
	}
}

func TestPathSelection(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GANTRY_ARTIFACTS", dir)
	if got, want := Path("asset"), filepath.Join(dir, "asset"); got != want {
		t.Fatalf("Path = %q, want %q", got, want)
	}
}

func TestGVisorVariantsAreIdempotent(t *testing.T) {
	rootfs := GVisorRootfs("nerdbox-rootfs-arm64.erofs")
	if want := "nerdbox-rootfs-gvisor-arm64.erofs"; rootfs != want {
		t.Fatalf("GVisorRootfs = %q, want %q", rootfs, want)
	}
	if got := GVisorRootfs(rootfs); got != rootfs {
		t.Fatalf("second GVisorRootfs = %q, want %q", got, rootfs)
	}

	kernel := GVisorKernel("gantry-kernel-arm64")
	if runtime.GOARCH == "arm64" {
		if kernel != "gantry-kernel-arm64-4k" {
			t.Fatalf("GVisorKernel = %q", kernel)
		}
		if got := GVisorKernel(kernel); got != kernel {
			t.Fatalf("second GVisorKernel = %q, want %q", got, kernel)
		}
	} else if kernel != "gantry-kernel-arm64" {
		t.Fatalf("non-arm64 GVisorKernel = %q", kernel)
	}
}
