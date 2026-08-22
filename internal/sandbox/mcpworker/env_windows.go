package mcpworker

import "os"

// workerEnvironment is the MCP role's Windows bootstrap allowlist. TLS root
// loading and Windows runtime APIs may need these OS paths; no user profile,
// proxy, credential, or Gantry environment is inherited.
func workerEnvironment() []string {
	var environment []string
	for _, name := range []string{"SystemRoot", "WINDIR", "SystemDrive", "TEMP", "TMP"} {
		if value := os.Getenv(name); value != "" {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}
