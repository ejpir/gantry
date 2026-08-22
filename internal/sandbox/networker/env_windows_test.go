package networker

import (
	"slices"
	"testing"
)

func TestWindowsNetworkEnvironmentIsRoleSpecific(t *testing.T) {
	for _, key := range []string{
		"SystemRoot", "WINDIR", "SystemDrive", "TEMP", "TMP",
		"GANTRY_DEBUG_RTC", "GANTRY_BOOT_PROFILE", "GANTRY_VHOST_STATS", "GANTRY_SECRET_TEST",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("PATH", `C:\host-tools`)
	t.Setenv("HOME", `C:\host-home`)
	t.Setenv("SystemRoot", `C:\Windows`)
	t.Setenv("TEMP", `C:\Temp`)
	t.Setenv("GANTRY_DEBUG_RTC", "1")
	t.Setenv("GANTRY_BOOT_PROFILE", "1")
	t.Setenv("GANTRY_SECRET_TEST", "must-not-cross")

	want := []string{`SystemRoot=C:\Windows`, `TEMP=C:\Temp`, "GODEBUG=netdns=go"}
	if got := workerEnv(); !slices.Equal(got, want) {
		t.Fatalf("network worker environment = %v, want %v", got, want)
	}
}
