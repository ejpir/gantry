package sandbox

import (
	"reflect"
	"testing"

	"github.com/ejpir/gantry/internal/client"
	"github.com/ejpir/gantry/internal/sandbox/config"
)

func TestSandboxGuestDiskLayoutKeepsWorkloadAndIDEIndependent(t *testing.T) {
	cfg := config.RunConfig{RW: true, RWLayer: "/work.ext4", DevContainers: true}
	layout := sandboxGuestDiskLayout(cfg)
	if layout.workloadImageDev != "/dev/vdb" || layout.ideImageDev != "/dev/vdc" ||
		layout.workloadRWDev != "/dev/vdd" || layout.ideRWDev != "/dev/vde" {
		t.Fatalf("flattened layout = %+v", layout)
	}

	workload := workloadRootfsMounts(cfg)
	ide := devContainersRootfsMounts(cfg)
	if workload[0].Source != "/dev/vdb" || workload[1].Source != "/dev/vdd" {
		t.Fatalf("workload mounts = %+v", workload)
	}
	if ide[0].Source != "/dev/vdc" || ide[1].Source != "/dev/vde" {
		t.Fatalf("IDE mounts = %+v", ide)
	}
}

func TestSandboxGuestDiskLayoutAccountsForLayerSet(t *testing.T) {
	cfg := config.RunConfig{
		LayerSet: &client.LayerSet{FSMeta: "/meta", Layers: []string{"/a", "/b"}},
		RW:       true, RWLayer: "/work.ext4", DevContainers: true,
	}
	layout := sandboxGuestDiskLayout(cfg)
	if layout.workloadImageDev != "/dev/vdb" ||
		!reflect.DeepEqual(layout.workloadLayerDevs, []string{"/dev/vdc", "/dev/vdd"}) ||
		layout.ideImageDev != "/dev/vde" || layout.workloadRWDev != "/dev/vdf" || layout.ideRWDev != "/dev/vdg" {
		t.Fatalf("layer-set layout = %+v", layout)
	}
}

func TestSandboxGuestDiskLayoutAllowsReadOnlyWorkload(t *testing.T) {
	cfg := config.RunConfig{DevContainers: true}
	layout := sandboxGuestDiskLayout(cfg)
	if layout.workloadRWDev != "" || layout.ideImageDev != "/dev/vdc" || layout.ideRWDev != "/dev/vdd" {
		t.Fatalf("read-only workload layout = %+v", layout)
	}
}
