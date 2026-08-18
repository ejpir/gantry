//go:build linux || darwin

package sandbox

import (
	"os"
	"testing"

	"github.com/ejpir/gantry/internal/networkworker"
	"github.com/ejpir/gantry/internal/sandbox/worker/workertest"
)

// TestNetWorkerHelperProcess is the re-exec target for the network-assembly
// tests: hookNetWorkerSpawnForTests points the spawned worker at this test
// binary running this test, which then becomes a real netstack worker.
func TestNetWorkerHelperProcess(t *testing.T) {
	if os.Getenv("GANTRY_TEST_NET_WORKER") != "1" {
		return
	}
	workertest.AssertStdinUnreadable()
	os.Exit(networkworker.Cmd())
}
