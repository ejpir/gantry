//go:build linux || darwin

package sandbox

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/workerproto"
)

func TestCloseShutdownDevicesCollectsFinalNetworkTrafficBeforeVMMClose(t *testing.T) {
	worker, data := startInProcessWorker(t, testWorkerConfig(t, `{"default":"allow"}`))
	recorder := netpol.NewTrafficRecorder(filepath.Join(t.TempDir(), netpol.TrafficFileName))
	worker.startTrafficSyncEvery(recorder, time.Hour)

	if err := workerproto.WriteFrame(data, workerTestFrame(t, "203.0.113.7", 6, 443)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		snapshot, err := worker.TrafficSnapshot()
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.TXPackets == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker traffic was not observed: %+v", snapshot)
		}
		time.Sleep(10 * time.Millisecond)
	}

	runner := &closeFailureRunner{done: make(chan struct{})}
	runner.onClose = func() error {
		if got := recorder.Snapshot().TXPackets; got != 1 {
			t.Fatalf("VMM closed before final network traffic merge: TXPackets = %d", got)
		}
		return nil
	}
	runtime := &daemonRuntime{
		runner: runner,
		network: &Network{
			Split:   true,
			Worker:  worker,
			Traffic: recorder,
			close:   worker.Close,
		},
	}
	t.Cleanup(runtime.network.Close)

	if err := runtime.closeShutdownDevices(); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 1 {
		t.Fatalf("runner Close called %d times", runner.calls)
	}
}
