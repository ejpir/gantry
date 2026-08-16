package dashboard

import dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"

// sanitizeSnapshot keeps terminal control sequences at the presentation
// boundary. Service implementations can therefore return ordinary domain
// strings without depending on terminal-specific escaping.
func sanitizeSnapshot(snapshot *dashboardapi.Snapshot) {
	for i := range snapshot.Sandboxes {
		row := &snapshot.Sandboxes[i]
		row.Name = safeUILine(row.Name)
		row.State = dashboardapi.SandboxState(safeUILine(string(row.State)))
		row.Image = safeUILine(row.Image)
		row.Runtime = safeUILine(row.Runtime)
		row.Kernel = safeUILine(row.Kernel)
		row.Secrets = safeUILine(row.Secrets)
		row.RWLayer = safeUILine(row.RWLayer)
		row.GVProxy = safeUILine(row.GVProxy)
		row.NetPolicy = safeUILine(row.NetPolicy)
		row.Proxy = safeUILine(row.Proxy)
		row.NoProxy = safeUILine(row.NoProxy)
		row.Dir = safeUILine(row.Dir)
		row.ConfigPath = safeUILine(row.ConfigPath)
	}
	for i := range snapshot.Traffic {
		row := &snapshot.Traffic[i]
		row.Sandbox = safeUILine(row.Sandbox)
		row.Host = safeUILine(row.Host)
		row.Address = safeUILine(row.Address)
		row.Protocol = safeUILine(row.Protocol)
	}
	for i := range snapshot.Rules {
		row := &snapshot.Rules[i]
		row.Sandbox = safeUILine(row.Sandbox)
		row.Action = safeUILine(row.Action)
		row.Target = safeUILine(row.Target)
		row.Proto = safeUILine(row.Proto)
		row.Ports = safeUILine(row.Ports)
		row.Source = safeUILine(row.Source)
		row.Policy = safeUILine(row.Policy)
	}
	for i := range snapshot.Mounts {
		row := &snapshot.Mounts[i]
		row.Sandbox = safeUILine(row.Sandbox)
		row.Tag = safeUILine(row.Tag)
		row.Host = safeUILine(row.Host)
		row.VM = safeUILine(row.VM)
		row.Guest = safeUILine(row.Guest)
		row.State = safeUILine(row.State)
		row.Error = safeUILine(row.Error)
	}
	for i := range snapshot.Ports {
		row := &snapshot.Ports[i]
		row.Sandbox = safeUILine(row.Sandbox)
		row.Bind = safeUILine(row.Bind)
		row.Proto = safeUILine(row.Proto)
		row.State = safeUILine(row.State)
		row.Error = safeUILine(row.Error)
	}
	for i := range snapshot.Secrets {
		row := &snapshot.Secrets[i]
		row.Sandbox = safeUILine(row.Sandbox)
		row.Name = safeUILine(row.Name)
		row.State = safeUILine(row.State)
	}
}
