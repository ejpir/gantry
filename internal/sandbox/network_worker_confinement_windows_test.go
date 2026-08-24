//go:build windows

package sandbox

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/networkworker"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/networker"
)

func TestWindowsAutoAttemptsConfinedNetworkWorker(t *testing.T) {
	failure := errors.New("injected Windows network-worker failure")
	called := false
	starter := func(networkworker.Config, string) (*networker.Worker, net.Conn, error) {
		called = true
		return nil, nil, failure
	}
	network, err := startNetworkWithWorkerStart(
		config.RunConfig{Net: true, ProcessIsolation: "auto"}, t.TempDir(), starter)
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	if !called {
		t.Fatal("auto mode did not attempt the Windows network worker")
	}
	if network.Split {
		t.Fatal("failed worker launch reported a split network worker")
	}
	found := false
	for _, detail := range network.Degraded {
		found = found || strings.Contains(detail, failure.Error())
	}
	if !found {
		t.Fatalf("missing Windows network-worker degradation: %v", network.Degraded)
	}
}

func TestWindowsAutoFallsBackForLoopbackPolicy(t *testing.T) {
	// A nil starter is deliberate: the host-loopback compatibility gate must
	// select the monolithic backend before any worker spawn is attempted.
	network, err := startNetworkWithWorkerStart(
		config.RunConfig{Net: true, AllowLN: true, ProcessIsolation: "auto"}, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	if network.Split {
		t.Fatal("loopback-capable auto mode reported a split network worker")
	}
	found := false
	for _, detail := range network.Degraded {
		found = found || strings.Contains(detail, "cannot use host loopback")
	}
	if !found {
		t.Fatalf("missing host-loopback degradation: %v", network.Degraded)
	}
}

func TestWindowsRequiredRejectsLoopbackPolicy(t *testing.T) {
	_, err := startNetworkWithWorkerStart(
		config.RunConfig{Net: true, AllowLN: true, ProcessIsolation: "required"}, t.TempDir(), nil)
	if err == nil || !strings.Contains(err.Error(), "cannot use host loopback") {
		t.Fatalf("required loopback-policy error = %v", err)
	}
}

func TestWindowsRequiredPropagatesNetworkWorkerFailure(t *testing.T) {
	failure := errors.New("injected Windows network-worker failure")
	called := false
	starter := func(networkworker.Config, string) (*networker.Worker, net.Conn, error) {
		called = true
		return nil, nil, failure
	}
	_, err := startNetworkWithWorkerStart(
		config.RunConfig{Net: true, ProcessIsolation: "required"}, t.TempDir(), starter)
	if !called {
		t.Fatal("required mode did not attempt the Windows network worker")
	}
	if err == nil || !strings.Contains(err.Error(), failure.Error()) {
		t.Fatalf("required mode error = %v", err)
	}
}
