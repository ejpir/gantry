package vmm

import (
	"errors"
	"testing"
)

func TestMachineLifecycleRunToClose(t *testing.T) {
	var state machineLifecycle
	if state.phase != machinePrepared {
		t.Fatalf("initial phase = %s", state.phase)
	}
	if err := state.beginRun(); err != nil {
		t.Fatal(err)
	}
	if state.phase != machineStarting || state.runDone == nil {
		t.Fatalf("after beginRun: phase=%s done=%v", state.phase, state.runDone)
	}
	if err := state.backendReady(); err != nil {
		t.Fatal(err)
	}
	if state.phase != machineRunning {
		t.Fatalf("after backendReady: phase=%s", state.phase)
	}
	if err := state.finishRun(); err != nil {
		t.Fatal(err)
	}
	if state.phase != machineExited {
		t.Fatalf("after finishRun: phase=%s", state.phase)
	}
	select {
	case <-state.runDone:
	default:
		t.Fatal("finishRun did not publish completion")
	}
	if done := state.beginStop(); done != nil {
		t.Fatal("exited machine unexpectedly required a Run join")
	}
	if err := state.finishClose(); err != nil {
		t.Fatal(err)
	}
	if state.phase != machineClosed {
		t.Fatalf("terminal phase = %s", state.phase)
	}
}

func TestMachineLifecycleStopDuringStartupRejectsBackend(t *testing.T) {
	m := &Machine{}
	if err := m.beginRun(); err != nil {
		t.Fatal(err)
	}
	m.resourceMu.Lock()
	done := m.lifecycle.beginStop()
	m.resourceMu.Unlock()
	if done == nil {
		t.Fatal("startup shutdown did not require a Run join")
	}
	if err := m.adoptBackend(closeFunc(func() error { return nil })); !errors.Is(err, errMachineClosed) {
		t.Fatalf("adoptBackend after stop = %v, want errMachineClosed", err)
	}
	if err := m.finishRun(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	default:
		t.Fatal("startup completion was not published")
	}
}

func TestMachineLifecycleRejectsInvalidTransitions(t *testing.T) {
	for _, test := range []struct {
		from machinePhase
		to   machinePhase
	}{
		{machinePrepared, machineRunning},
		{machineStarting, machineClosed},
		{machineRunning, machinePrepared},
		{machineExited, machineRunning},
		{machineStopping, machineRunning},
		{machineClosed, machinePrepared},
	} {
		state := machineLifecycle{phase: test.from}
		if err := state.transition(test.to); err == nil {
			t.Errorf("transition %s -> %s succeeded", test.from, test.to)
		}
		if state.phase != test.from {
			t.Errorf("rejected transition changed phase to %s", state.phase)
		}
	}
}
