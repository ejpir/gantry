//go:build linux || darwin

package vmmworker

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ejpir/gantry/internal/workerconf"
	"github.com/ejpir/gantry/internal/workerproto"
)

type countingRunner struct {
	closes      atomic.Int32
	hotRequests atomic.Int32
}

func (*countingRunner) Run() error                             { return nil }
func (runner *countingRunner) Close() error                    { runner.closes.Add(1); return nil }
func (runner *countingRunner) RequestHotMemory() error         { runner.hotRequests.Add(1); return nil }
func (*countingRunner) InjectVsockConn(uint32, net.Conn) error { return nil }

func TestKeepFDsMatchesDescriptorTable(t *testing.T) {
	base := keepFDs(Config{})
	if base != 9 {
		t.Fatalf("base keepFDs = %d, want 9", base)
	}
	full := keepFDs(Config{HasRoot: true, NDisksRO: 2, NDisks: 1, HasKVM: true})
	if full != base+5 {
		t.Fatalf("full keepFDs = %d, want %d", full, base+5)
	}
}

func TestConfigRejectsUnboundedDescriptorTables(t *testing.T) {
	for _, config := range []Config{
		{NDisksRO: -1},
		{NDisks: -1},
		{NDisksRO: maxInheritedDisks, NDisks: 1},
		{NDisks: 2, DisksPrelocked: true, MaxWritableFileSize: 1},
	} {
		if err := config.validate(); err == nil {
			t.Fatalf("validate(%+v) succeeded", config)
		}
	}
	if err := (Config{NDisksRO: maxInheritedDisks - 1, NDisks: 1, DisksPrelocked: true, MaxWritableFileSize: 1}).validate(); err != nil {
		t.Fatalf("valid descriptor table: %v", err)
	}
}

func TestRequiredConfinementPropertiesArePlatformSpecific(t *testing.T) {
	has := func(items []string, want string) bool {
		for _, item := range items {
			if item == want {
				return true
			}
		}
		return false
	}
	linux := requiredConfinementProperties("linux")
	if !has(linux, workerconf.PropFDTable) || !has(linux, workerconf.PropSyscall) || !has(linux, workerconf.PropLandlock) || !has(linux, workerconf.PropProcEnum) || !has(linux, workerconf.PropTaskLimit) || has(linux, workerconf.PropProcSignal) {
		t.Fatalf("Linux required properties = %v", linux)
	}
	darwin := requiredConfinementProperties("darwin")
	if !has(darwin, workerconf.PropProcSignal) || !has(darwin, workerconf.PropProcEnum) || has(darwin, workerconf.PropTaskLimit) {
		t.Fatalf("Darwin required properties = %v", darwin)
	}
}

func TestRunnerCloseIsIdempotent(t *testing.T) {
	runner := new(countingRunner)
	state := workerState{runner: runner}
	const callers = 32
	var calls sync.WaitGroup
	calls.Add(callers)
	for range callers {
		go func() {
			defer calls.Done()
			if err := state.closeRunner(); err != nil {
				t.Errorf("close runner: %v", err)
			}
		}()
	}
	calls.Wait()
	if got := runner.closes.Load(); got != 1 {
		t.Fatalf("runner closes = %d, want 1", got)
	}
}

func TestHotMemoryRequestReachesRunner(t *testing.T) {
	runner := new(countingRunner)
	state := workerState{runner: runner}
	if _, err := state.requestHotMemory(workerproto.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := runner.hotRequests.Load(); got != 1 {
		t.Fatalf("hot-memory requests = %d, want 1", got)
	}
}

// Split-net topology sends no policy to the VMM worker: the network worker
// enforces. The absence has to reach virtio-net as a genuinely nil
// interface — a typed-nil *netpol.Policy passes the device's `!= nil` guard
// and panics on the first frame the guest receives (a DHCP offer was enough
// to kill the worker mid-boot).
func TestNetDeviceHooksAbsentPolicyIsNilInterface(t *testing.T) {
	policy, traffic, err := workerNetworkState(nil)
	if err != nil {
		t.Fatal(err)
	}
	devicePolicy, deviceTraffic := netDeviceHooks(policy, traffic)
	if devicePolicy != nil {
		t.Errorf("device policy = %#v, want a nil interface", devicePolicy)
	}
	if deviceTraffic != nil {
		t.Errorf("device traffic observer = %#v, want a nil interface", deviceTraffic)
	}
}

func TestNetDeviceHooksCarryPresentPolicy(t *testing.T) {
	policy, traffic, err := workerNetworkState([]byte(`{"defaultAllow":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if policy == nil {
		t.Fatal("parsed policy is nil")
	}
	defer traffic.Close()
	devicePolicy, deviceTraffic := netDeviceHooks(policy, traffic)
	if devicePolicy == nil || deviceTraffic == nil {
		t.Fatalf("device hooks = (%v, %v), want both installed", devicePolicy, deviceTraffic)
	}
}
