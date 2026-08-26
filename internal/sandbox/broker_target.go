package sandbox

import (
	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/image"

	"github.com/containerd/containerd/api/types"
)

const (
	workloadBaseContainerID = "sb"
	ideBaseContainerID      = "sb-ide"
)

type brokerSessionTarget struct {
	baseID           string
	rw               bool
	rootfs           []*types.Mount
	imageConfig      *image.Config
	nestedContainers bool
}

func (br *broker) sessionTarget(ide bool) brokerSessionTarget {
	if ide && br.cfg.DevContainers {
		return brokerSessionTarget{
			baseID: ideBaseContainerID, rw: true,
			rootfs:      devContainersRootfsMounts(br.cfg),
			imageConfig: br.cfg.DevContainersImageCfg, nestedContainers: true,
		}
	}
	return brokerSessionTarget{
		baseID: workloadBaseContainerID, rw: br.cfg.RW,
		rootfs: workloadRootfsMounts(br.cfg), imageConfig: br.cfg.ImageCfg,
	}
}

func applySessionTarget(options *client.SessionOptions, target brokerSessionTarget) {
	options.ID = target.baseID
	options.RW = target.rw
	options.RootfsMountsOverride = target.rootfs
	options.ImgCfg = target.imageConfig
	options.NestedContainers = target.nestedContainers
}
