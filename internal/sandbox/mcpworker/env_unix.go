//go:build linux || darwin

package mcpworker

// The MCP worker resolves no environment-backed paths or destinations. System
// TLS roots are loaded from platform defaults before confinement.
func workerEnvironment() []string { return []string{} }
