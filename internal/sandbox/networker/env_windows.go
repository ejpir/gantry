package networker

import "os"

// workerEnv is the Windows network role's explicit environment allowlist.
// The OS bootstrap paths required by the runtime and Winsock are retained;
// host secrets, account TEMP paths, and general GANTRY_* settings are absent.
func workerEnv() []string {
	out := make([]string, 0, 4)
	for _, key := range []string{"SystemRoot", "WINDIR", "SystemDrive"} {
		if value := os.Getenv(key); value != "" {
			out = append(out, key+"="+value)
		}
	}
	return append(out, "GODEBUG=netdns=go")
}
