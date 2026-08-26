package sandbox

import (
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/sandbox/config"
)

func TestPrepareDevContainersProfileAddsPeerWithoutReplacingWorkload(t *testing.T) {
	oldEnsureImage, oldEnsureLayer, oldCheckPairing := ensureDevContainersImageAsset, ensureDevContainersRWLayer, checkDevContainersRWPairing
	t.Cleanup(func() {
		ensureDevContainersImageAsset, ensureDevContainersRWLayer, checkDevContainersRWPairing = oldEnsureImage, oldEnsureLayer, oldCheckPairing
	})
	ideImage := filepath.Join(t.TempDir(), "ide.erofs")
	ideLayer := filepath.Join(t.TempDir(), "ide.ext4")
	ensureDevContainersImageAsset = func(string, func(string, ...any)) (string, error) { return ideImage, nil }
	ensureDevContainersRWLayer = func(name, imageID string, size uint, _ func(string, ...any)) (string, []string, error) {
		if name != "dev@devcontainers" || imageID != ideImage || size != 8192 {
			t.Fatalf("IDE layer request = name %q image %q size %d", name, imageID, size)
		}
		return ideLayer, nil, nil
	}
	checkDevContainersRWPairing = func(layer, imageID string) error {
		if layer != ideLayer || imageID != ideImage {
			t.Fatalf("IDE pairing = layer %q image %q", layer, imageID)
		}
		return nil
	}
	workloadConfig := &image.Config{User: "app", UID: 2000}
	before := config.RunConfig{
		DevContainers: true, SSH: true, Runtime: "crun",
		Image: "/images/workload.erofs", ImageCfg: workloadConfig,
		RWLayerSizeMiB: 8192,
	}
	after, changed, _, err := prepareDevContainersProfile("dev", before, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("legacy profile was not migrated")
	}
	if after.Image != before.Image || after.ImageCfg != workloadConfig {
		t.Fatalf("workload image changed: before=%+v after=%+v", before, after)
	}
	if after.DevContainersImage != ideImage || after.DevContainersRWLayer != ideLayer ||
		after.DevContainersImageCfg == nil || after.DevContainersImageCfg.User != "gantry" {
		t.Fatalf("IDE peer profile = %+v", after)
	}
}
