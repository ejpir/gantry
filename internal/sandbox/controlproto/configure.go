package controlproto

import "github.com/ejpir/gantry/internal/sandbox/config"

// SandboxUpdate is the canonical wire-to-store conversion for explicitly
// supplied mutable settings.
func (request ConfigureRequest) SandboxUpdate() config.SandboxUpdate {
	return config.SandboxUpdate{
		SSH: request.SSH, DevContainers: request.DevContainers,
		MemMB: request.MemMB, VCPUs: request.VCPUs,
		ProcessIsolation: request.ProcessIsolation,
	}
}

// ConfigureRequestFor converts a complete settings value to the pointer-based
// wire shape used for partial configure requests.
func ConfigureRequestFor(settings config.MutableSandboxSettings) ConfigureRequest {
	return ConfigureRequest{
		SSH: &settings.SSH, DevContainers: &settings.DevContainers,
		MemMB: &settings.MemMB, VCPUs: &settings.VCPUs,
		ProcessIsolation: &settings.ProcessIsolation,
	}
}
