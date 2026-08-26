package sandbox

import (
	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/sandbox/config"

	"github.com/containerd/containerd/api/types"
)

type sandboxDiskLayout struct {
	workloadImageDev  string
	workloadLayerDevs []string
	workloadRWDev     string
	ideImageDev       string
	ideRWDev          string
}

// sandboxGuestDiskLayout mirrors vm_config.go: the system root is vda, every
// read-only workload/IDE image follows, then every writable layer. Keeping the
// calculation centralized prevents a second image from silently shifting the
// workload writable device underneath vminitd.
func sandboxGuestDiskLayout(cfg config.RunConfig) sandboxDiskLayout {
	layout := sandboxDiskLayout{workloadImageDev: client.BlkDevName(1)}
	workloadRO := 1
	if cfg.LayerSet != nil {
		workloadRO = 1 + len(cfg.LayerSet.Layers)
		layout.workloadLayerDevs = make([]string, len(cfg.LayerSet.Layers))
		for index := range layout.workloadLayerDevs {
			layout.workloadLayerDevs[index] = client.BlkDevName(2 + index)
		}
	}
	totalRO := workloadRO
	if cfg.DevContainers {
		layout.ideImageDev = client.BlkDevName(1 + workloadRO)
		totalRO++
	}
	nextWritable := 1 + totalRO
	if cfg.RW && cfg.RWLayer != "" {
		layout.workloadRWDev = client.BlkDevName(nextWritable)
		nextWritable++
	}
	if cfg.DevContainers {
		layout.ideRWDev = client.BlkDevName(nextWritable)
	}
	return layout
}

func workloadRootfsMounts(cfg config.RunConfig) []*types.Mount {
	layout := sandboxGuestDiskLayout(cfg)
	return client.RootfsMountsDevices(cfg.RW, layout.workloadImageDev,
		layout.workloadLayerDevs, layout.workloadRWDev)
}

func devContainersRootfsMounts(cfg config.RunConfig) []*types.Mount {
	if !cfg.DevContainers {
		return nil
	}
	layout := sandboxGuestDiskLayout(cfg)
	return client.RootfsMountsDevices(true, layout.ideImageDev, nil, layout.ideRWDev)
}
