package sshgw

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestOwnerStopsAndJoinsServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var owner Owner
	started := make(chan struct{})
	exited := make(chan struct{})
	if !owner.Start(listener, func(ctx context.Context, _ net.Listener) {
		close(started)
		<-ctx.Done()
		close(exited)
	}) {
		t.Fatal("owner rejected its first listener")
	}
	<-started
	if !owner.Running() {
		t.Fatal("owner did not report its live gateway")
	}

	owner.Stop()
	if owner.Running() {
		t.Fatal("owner remained running after stop")
	}
	select {
	case <-exited:
	default:
		t.Fatal("Stop returned before the serving goroutine exited")
	}
	owner.Stop()
}

func TestOwnerRejectsReplacementUntilStopped(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()

	var owner Owner
	var starts atomic.Int32
	if !owner.Start(first, func(ctx context.Context, _ net.Listener) {
		starts.Add(1)
		<-ctx.Done()
	}) {
		t.Fatal("owner rejected first listener")
	}
	deadline := time.Now().Add(time.Second)
	for starts.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if owner.Start(second, func(context.Context, net.Listener) {}) {
		t.Fatal("owner accepted a second live listener")
	}
	owner.Stop()
}
