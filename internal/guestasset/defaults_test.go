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
	if got := DefaultKernel(); filepath.Base(got) != gantry {
		t.Errorf("stock kernel silently selected: got %s, want .../%s", got, gantry)
	}
	if err := os.WriteFile(filepath.Join(dir, gantry), []byte("hardened"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DefaultKernel(); filepath.Base(got) != gantry {
		t.Errorf("both staged: got %s, want .../%s", got, gantry)
	}
}

func TestReleaseAssetsUseVersionedUserCache(t *testing.T) {
	oldVersion, oldCache, oldHome, oldTemp := Version, userCacheDir, userHomeDir, systemTempDir
	t.Cleanup(func() {
		Version, userCacheDir, userHomeDir, systemTempDir = oldVersion, oldCache, oldHome, oldTemp
	})
	t.Setenv("GANTRY_ARTIFACTS", "")
	Version = "v1.2.3"
	cache := t.TempDir()
	userCacheDir = func() (string, error) { return cache, nil }
	userHomeDir = func() (string, error) { return t.TempDir(), nil }

	gantry, nerdbox := kernelNames(runtime.GOARCH)
	// A legacy stock kernel in the working directory must not affect a tagged
	// release. This is the upgrade failure that previously kept Windows VMs on
	// the old kernel after only the release executable was replaced.
	working := t.TempDir()
	t.Chdir(working)
	if err := os.WriteFile(nerdbox, []byte("old stock kernel"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gantry, []byte("old owned kernel"), 0o644); err != nil {
		t.Fatal(err)
	}

	wantKernel := filepath.Join(cache, "gantry", "assets", Version, gantry)
	if got := DefaultKernel(); got != wantKernel {
		t.Fatalf("DefaultKernel = %q, want %q", got, wantKernel)
	}
	rootfs := "nerdbox-rootfs-arm64.erofs"
	if runtime.GOARCH == "amd64" {
		rootfs = "nerdbox-rootfs-x86_64.erofs"
	}
	wantRootfs := filepath.Join(cache, "gantry", "assets", Version, rootfs)
	if got := DefaultRootfs(); got != wantRootfs {
		t.Fatalf("DefaultRootfs = %q, want %q", got, wantRootfs)
	}
	image := "gantry-default-image-arm64.erofs"
	if runtime.GOARCH == "amd64" {
		image = "gantry-default-image-x86_64.erofs"
	}
	wantImage := filepath.Join(cache, "gantry", "assets", Version, image)
	if got := DefaultImage(); got != wantImage {
		t.Fatalf("DefaultImage = %q, want %q", got, wantImage)
	}
}

func TestReleaseAssetCacheFallsBackToUserHome(t *testing.T) {
	oldVersion, oldCache, oldHome, oldTemp := Version, userCacheDir, userHomeDir, systemTempDir
	t.Cleanup(func() {
		Version, userCacheDir, userHomeDir, systemTempDir = oldVersion, oldCache, oldHome, oldTemp
	})
	t.Setenv("GANTRY_ARTIFACTS", "")
	Version = "v1.2.3"
	userCacheDir = func() (string, error) { return "", os.ErrNotExist }
	home := t.TempDir()
	userHomeDir = func() (string, error) { return home, nil }

	gantry, _ := kernelNames(runtime.GOARCH)
	want := filepath.Join(home, ".gantry", "assets", Version, gantry)
	if got := DefaultKernel(); got != want {
		t.Fatalf("DefaultKernel = %q, want user-home fallback %q", got, want)
	}
}

func TestReleaseAssetCacheNeverFallsBackToWorkingDirectory(t *testing.T) {
	oldVersion, oldCache, oldHome, oldTemp := Version, userCacheDir, userHomeDir, systemTempDir
	t.Cleanup(func() {
		Version, userCacheDir, userHomeDir, systemTempDir = oldVersion, oldCache, oldHome, oldTemp
	})
	t.Setenv("GANTRY_ARTIFACTS", "")
	Version = "v1.2.3"
	userCacheDir = func() (string, error) { return "", os.ErrNotExist }
	userHomeDir = func() (string, error) { return "", os.ErrNotExist }
	temp := t.TempDir()
	systemTempDir = func() string { return temp }

	gantry, _ := kernelNames(runtime.GOARCH)
	want := filepath.Join(temp, "gantry", "assets", Version, gantry)
	if got := DefaultKernel(); got != want {
		t.Fatalf("DefaultKernel = %q, want temp fallback %q", got, want)
	}
}

func TestGantryArtifactsOverridesReleaseCache(t *testing.T) {
	oldVersion := Version
	t.Cleanup(func() { Version = oldVersion })
	Version = "v1.2.3"
	dir := t.TempDir()
	t.Setenv("GANTRY_ARTIFACTS", dir)
	gantry, _ := kernelNames(runtime.GOARCH)
	if got, want := DefaultKernel(), filepath.Join(dir, gantry); got != want {
		t.Fatalf("DefaultKernel = %q, want explicit override %q", got, want)
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

func TestIsManagedReleaseKernel(t *testing.T) {
	gantry, _ := kernelNames(runtime.GOARCH)
	managed := filepath.Join(t.TempDir(), "gantry", "assets", "v0.0.7", gantry)
	if !IsManagedReleaseKernel(managed) {
		t.Fatalf("versioned Gantry kernel was not recognized: %s", managed)
	}
	if runtime.GOARCH == "arm64" && !IsManagedReleaseKernel(managed+"-4k") {
		t.Fatalf("versioned Gantry 4K kernel was not recognized: %s-4k", managed)
	}

	for _, path := range []string{
		filepath.Join(t.TempDir(), gantry),
		filepath.Join(t.TempDir(), "gantry", "assets", "latest", gantry),
		filepath.Join(t.TempDir(), "other", "assets", "v0.0.7", gantry),
		filepath.Join(t.TempDir(), "gantry", "assets", "v0.0.7", "custom-kernel"),
	} {
		if IsManagedReleaseKernel(path) {
			t.Errorf("custom/ambiguous path was recognized as managed: %s", path)
		}
	}
}
