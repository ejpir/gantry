//go:build windows

package sandbox

import (
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/networker"
)

func TestWindowsAutoSkipsUnavailableNetworkWorkerConfinement(t *testing.T) {
	called := false
	old := networker.SpawnHook
	networker.SpawnHook = func(*[]string, *[]string) { called = true }
	t.Cleanup(func() { networker.SpawnHook = old })

	network, err := startNetwork(config.RunConfig{Net: true, ProcessIsolation: "auto"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	if called {
		t.Fatal("auto mode spawned a network worker whose confinement is unavailable")
	}
	if network.Split {
		t.Fatal("auto mode reported a split network worker")
	}
	found := false
	for _, detail := range network.Degraded {
		found = found || strings.Contains(detail, "confinement unavailable on windows")
	}
	if !found {
		t.Fatalf("missing Windows network-worker degradation: %v", network.Degraded)
	}
}

func TestWindowsRequiredRejectsUnavailableNetworkWorkerConfinement(t *testing.T) {
	called := false
	old := networker.SpawnHook
	networker.SpawnHook = func(*[]string, *[]string) { called = true }
	t.Cleanup(func() { networker.SpawnHook = old })

	_, err := startNetwork(config.RunConfig{Net: true, ProcessIsolation: "required"}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "confinement unavailable on windows") {
		t.Fatalf("required mode error = %v", err)
	}
	if called {
		t.Fatal("required mode spawned a network worker after detecting unavailable confinement")
	}
}
