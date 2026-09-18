package sandbox

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestSSHGatewayOwnerStopsAndJoinsServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var owner sshGatewayOwner
	started := make(chan struct{})
	exited := make(chan struct{})
	if !owner.start(listener, func(ctx context.Context, _ net.Listener) {
		close(started)
		<-ctx.Done()
		close(exited)
	}) {
		t.Fatal("owner rejected its first listener")
	}
	<-started
	if !owner.running() {
		t.Fatal("owner did not report its live gateway")
	}

	owner.stop()
	if owner.running() {
		t.Fatal("owner remained running after stop")
	}
	select {
	case <-exited:
	default:
		t.Fatal("stop returned before the serving goroutine exited")
	}
	// Teardown is idempotent because daemon shutdown and live reconfiguration
	// may both observe the same gateway.
	owner.stop()
}

func TestSSHGatewayOwnerRejectsReplacementUntilStopped(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()

	var owner sshGatewayOwner
	var starts atomic.Int32
	if !owner.start(first, func(ctx context.Context, _ net.Listener) {
		starts.Add(1)
		<-ctx.Done()
	}) {
		t.Fatal("owner rejected first listener")
	}
	deadline := time.Now().Add(time.Second)
	for starts.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if owner.start(second, func(context.Context, net.Listener) {}) {
		t.Fatal("owner accepted a second live listener")
	}
	owner.stop()
}
