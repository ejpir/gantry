package dashboardsvc

import (
	"runtime"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
)

func TestDashboardMaxMemoryMB(t *testing.T) {
	for _, test := range []struct {
		name  string
		bytes uint64
		want  uint
	}{
		{"16 GiB host", 16 << 30, 16 << 10},
		{"24 GiB host", 24 << 30, 24 << 10},
		{"round down to MiB", (8 << 30) + (1 << 20) - 1, 8 << 10},
		{"architectural ceiling", 2 << 40, config.MaxSandboxMemMB},
		{"detection failure", 0, 512},
		{"below VM minimum", 1 << 20, config.MinSandboxMemMB},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := dashboardMaxMemoryMB(test.bytes); got != test.want {
				t.Fatalf("maximum memory = %d MiB, want %d", got, test.want)
			}
		})
	}
}

func TestDashboardResourceLimitsUseHostMemory(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("host memory detection is not supported")
	}
	total := hostMemoryBytes()
	if total == 0 {
		t.Fatal("could not detect physical host memory")
	}
	limits := (dashboardService{}).ResourceLimits()
	if got, want := limits.MaxMemoryMB, dashboardMaxMemoryMB(total); got != want {
		t.Fatalf("maximum memory = %d MiB, want %d", got, want)
	}
}
