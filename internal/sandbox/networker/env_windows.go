package networker

import "os"

// workerEnv is the Windows network role's explicit environment allowlist.
// These OS paths are required for runtime and Winsock bootstrap; host secrets
// and general GANTRY_* settings are deliberately absent.
func workerEnv() []string {
	out := make([]string, 0, 6)
	for _, key := range []string{"SystemRoot", "WINDIR", "SystemDrive", "TEMP", "TMP"} {
		if value := os.Getenv(key); value != "" {
			out = append(out, key+"="+value)
		}
	}
	return append(out, "GODEBUG=netdns=go")
}
