//go:build windows

package sandbox

import (
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/config"
)

func TestWindowsAutoSkipsUnavailableNetworkWorkerConfinement(t *testing.T) {
	// A nil starter is deliberate: an attempted split-worker spawn panics and
	// fails the test before the monolithic fallback can hide the regression.
	network, err := startNetworkWithWorkerStart(
		config.RunConfig{Net: true, ProcessIsolation: "auto"}, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
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
	_, err := startNetworkWithWorkerStart(
		config.RunConfig{Net: true, ProcessIsolation: "required"}, t.TempDir(), nil)
	if err == nil || !strings.Contains(err.Error(), "confinement unavailable on windows") {
		t.Fatalf("required mode error = %v", err)
	}
}
