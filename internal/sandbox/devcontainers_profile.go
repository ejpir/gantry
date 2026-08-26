package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/ejpir/gantry/internal/guestasset"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/rwlayer"
)

var (
	ensureDevContainersImageAsset = guestasset.EnsureImage
	ensureDevContainersRWLayer    = rwlayer.Default
	checkDevContainersRWPairing   = rwlayer.CheckPairing
)

func defaultDevContainersImageConfig() *image.Config {
	return &image.Config{
		Env: []string{
			"HOME=/home/gantry",
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		},
		Cmd: []string{"/bin/bash"}, User: "gantry", UID: 1000, GID: 1000,
		WorkingDir: "/home/gantry",
	}
}

// prepareDevContainersProfile resolves the second OCI root attached to a
// sandbox VM. The workload image remains untouched: normal exec sessions use
// it, while SSH and nested Podman sessions use this curated IDE root.
func prepareDevContainersProfile(name string, cfg config.RunConfig, progress func(string, ...any)) (config.RunConfig, bool, []string, error) {
	if !cfg.DevContainers {
		return cfg, false, nil, nil
	}
	if name == "" {
		return cfg, false, nil, fmt.Errorf("dev containers require a named persistent sandbox")
	}
	before := cfg

	// Pin an existing IDE lower layer just like a workload image. Silently
	// replacing it on every Gantry update would invalidate the paired overlay
	// and strand persistent Podman images and editor state.
	ideImage := cfg.DevContainersImage
	if ideImage != "" {
		if _, err := os.Stat(ideImage); err != nil && !os.IsNotExist(err) {
			return before, false, nil, fmt.Errorf("inspect curated Dev Containers image: %w", err)
		} else if os.IsNotExist(err) {
			ideImage = ""
		}
	}
	if ideImage == "" {
		var err error
		ideImage, err = ensureDevContainersImageAsset(guestasset.DefaultDevContainersImage(), progress)
		if err != nil {
			return before, false, nil, fmt.Errorf("prepare curated Dev Containers image: %w", err)
		}
	}
	var err error
	ideImage, err = filepath.Abs(ideImage)
	if err != nil {
		return before, false, nil, fmt.Errorf("resolve curated Dev Containers image: %w", err)
	}
	cfg.DevContainersImage = ideImage
	cfg.DevContainersImageCfg = defaultDevContainersImageConfig()

	diskMiB := cfg.DevContainersDiskMiB
	if diskMiB == 0 {
		diskMiB = cfg.RWLayerSizeMiB
	}
	if diskMiB == 0 {
		diskMiB = config.DefaultDevContainersDiskSizeMiB
	}
	if err := config.ValidateRWLayerSize(diskMiB); err != nil {
		return before, false, nil, fmt.Errorf("dev containers writable layer: %w", err)
	}
	layer, warnings, err := ensureDevContainersRWLayer(
		rwlayer.DevContainersName(name), ideImage, diskMiB, progress)
	if err != nil {
		return before, false, warnings, fmt.Errorf("prepare Dev Containers writable layer: %w", err)
	}
	layer, err = filepath.Abs(layer)
	if err != nil {
		return before, false, warnings, fmt.Errorf("resolve Dev Containers writable layer: %w", err)
	}
	if warning := rwlayer.HealthWarning(layer); warning != "" {
		warnings = append(warnings, warning)
	}
	if err := checkDevContainersRWPairing(layer, ideImage); err != nil {
		return before, false, warnings, fmt.Errorf("dev containers writable layer: %w", err)
	}
	cfg.DevContainersRWLayer = layer
	cfg.DevContainersDiskMiB = diskMiB

	changed := before.DevContainersImage != cfg.DevContainersImage ||
		before.DevContainersRWLayer != cfg.DevContainersRWLayer ||
		before.DevContainersDiskMiB != cfg.DevContainersDiskMiB ||
		!reflect.DeepEqual(before.DevContainersImageCfg, cfg.DevContainersImageCfg)
	return cfg, changed, warnings, nil
}
