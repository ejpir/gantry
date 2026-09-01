package sandbox

import (
	"github.com/ejpir/gantry/internal/guestasset"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/sandbox/config"
	devcontainersprofile "github.com/ejpir/gantry/internal/sandbox/devcontainers"
	"github.com/ejpir/gantry/internal/sandbox/rwlayer"
)

var (
	ensureDevContainersImageAsset = guestasset.EnsureImage
	verifyDevContainersImageAsset = devcontainersprofile.VerifyImage
	ensureDevContainersRWLayer    = rwlayer.Default
	checkDevContainersRWPairing   = rwlayer.CheckPairing
)

func defaultDevContainersImageConfig() *image.Config {
	return devcontainersprofile.ImageConfig()
}

// curatedDevContainersImageConfig restores the OCI metadata that docker
// export necessarily drops when scripts/mkideimage.sh flattens the curated
// image to EROFS. Match the canonical release-asset basename so the same
// artifact behaves correctly when supplied directly through -image as well as
// when prepareDevContainersProfile attaches it as the IDE peer root.
func curatedDevContainersImageConfig(path string) *image.Config {
	return devcontainersprofile.CuratedImageConfig(path)
}

// prepareDevContainersProfile resolves the second OCI root attached to a
// sandbox VM. The workload image remains untouched: normal exec sessions use
// it, while SSH and nested Podman sessions use this curated IDE root.
func prepareDevContainersProfile(name string, cfg config.RunConfig, progress func(string, ...any)) (config.RunConfig, bool, []string, error) {
	return devcontainersprofile.PrepareWith(name, cfg, progress, devcontainersprofile.Dependencies{
		EnsureImage:  ensureDevContainersImageAsset,
		VerifyImage:  verifyDevContainersImageAsset,
		EnsureLayer:  ensureDevContainersRWLayer,
		CheckPairing: checkDevContainersRWPairing,
	})
}
