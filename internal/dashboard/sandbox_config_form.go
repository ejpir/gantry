package dashboard

import dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"

type sandboxFeatureControls struct {
	ssh, devContainers *bool
	cpus, memory       *resourceSlider
	disk               *resourceSlider
	runtime            *string
}

func (controls sandboxFeatureControls) toggleSSH() {
	*controls.ssh = !*controls.ssh
	if !*controls.ssh {
		*controls.devContainers = false
	}
}

func (m *sandboxTUIModel) toggleDevContainers(controls sandboxFeatureControls) {
	*controls.devContainers = !*controls.devContainers
	if !*controls.devContainers {
		return
	}
	*controls.ssh = true
	controls.cpus.Set(maxInt(controls.cpus.Value, m.limits.DefaultDevContainersVCPUs))
	controls.memory.Set(maxInt(controls.memory.Value, int(m.limits.DefaultDevContainersMemoryMiB)))
	if controls.disk != nil {
		controls.disk.Set(maxInt(controls.disk.Value, int(m.limits.DefaultDevContainersDiskMiB)))
	}
	if controls.runtime != nil {
		*controls.runtime = createRuntimeCrun
	}
}

type sandboxConfigForm struct {
	name, isolation    string
	ssh, devContainers bool
	memory, cpus       resourceSlider
}

func (form sandboxConfigForm) request() dashboardapi.SandboxConfigRequest {
	return dashboardapi.SandboxConfigRequest{
		Name: form.name, SSH: form.ssh, DevContainers: form.devContainers,
		MemMB: uint(form.memory.Value), VCPUs: form.cpus.Value, ProcessIsolation: form.isolation,
	}
}
