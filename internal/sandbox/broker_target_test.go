package sandbox

import (
	"testing"

	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/sandbox/config"
)

func TestSSHImageConfigSelectsIDEPeer(t *testing.T) {
	workload := &image.Config{User: "app"}
	ide := &image.Config{User: "gantry"}
	cfg := config.RunConfig{ImageCfg: workload, DevContainersImageCfg: ide}
	if got := sshImageConfig(cfg); got != workload {
		t.Fatalf("ordinary SSH config = %+v", got)
	}
	cfg.DevContainers = true
	if got := sshImageConfig(cfg); got != ide {
		t.Fatalf("Dev Containers SSH config = %+v", got)
	}
}

func TestBrokerSessionTargetsKeepExecAndIDESeparate(t *testing.T) {
	workloadConfig := &image.Config{User: "app", UID: 123}
	ideConfig := &image.Config{User: "gantry", UID: 1000}
	br := &broker{cfg: config.RunConfig{
		RW: true, RWLayer: "/work.ext4", ImageCfg: workloadConfig,
		DevContainers: true, DevContainersImageCfg: ideConfig,
		DevContainersRWLayer: "/ide.ext4",
	}}

	workload := br.sessionTarget(false)
	if workload.baseID != workloadBaseContainerID || workload.imageConfig != workloadConfig || workload.nestedContainers {
		t.Fatalf("workload target = %+v", workload)
	}
	ide := br.sessionTarget(true)
	if ide.baseID != ideBaseContainerID || ide.imageConfig != ideConfig || !ide.nestedContainers || !ide.rw {
		t.Fatalf("IDE target = %+v", ide)
	}
	if workload.rootfs[0].Source == ide.rootfs[0].Source {
		t.Fatalf("workload and IDE share image device %s", workload.rootfs[0].Source)
	}
}
