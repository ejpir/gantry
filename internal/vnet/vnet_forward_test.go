package vnet

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

// Publish/List/Unpublish ride the stack's own services mux in-process; the
// listeners are real host sockets, so this covers the full lifecycle
// including the bind-conflict path, without needing a guest.
func TestForwardLifecycle(t *testing.T) {
	stack, err := Start([6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	local := l.Addr().String()
	l.Close()

	if err := stack.Publish("tcp", local, GuestIP+":80"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// The host listener is live: a connect succeeds at TCP level even
	// though the guest side has nothing to answer.
	probe, err := net.Dial("tcp", local)
	if err != nil {
		t.Fatalf("host listener not accepting: %v", err)
	}
	probe.Close()

	forwards, err := stack.Forwards()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range forwards {
		if f.Local == local && f.Remote == GuestIP+":80" && f.Protocol == "tcp" {
			found = true
		}
	}
	if !found {
		t.Fatalf("forward %v not listed in %+v", local, forwards)
	}

	if err := stack.Publish("tcp", local, GuestIP+":80"); err == nil ||
		!strings.Contains(err.Error(), "already running") {
		t.Fatalf("duplicate publish: want already-running error, got %v", err)
	}

	if err := stack.Unpublish("tcp", local); err != nil {
		t.Fatalf("unpublish: %v", err)
	}
	if _, err := net.Dial("tcp", local); err == nil {
		t.Fatal("listener still accepting after unpublish")
	}
}

// Static forwards handed to Start are live from the first packet; a busy
// host port fails stack creation loudly (the boot-time conflict path).
func TestStartWithForwards(t *testing.T) {
	// UDP exercises the "udp:" key prefix path end to end.
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	udpLocal := pc.LocalAddr().String()
	pc.Close()

	forwards := map[string]string{
		"udp:" + udpLocal: GuestIP + ":53",
	}
	stack, err := Start([6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}, forwards)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	list, err := stack.Forwards()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range list {
		if f.Local == udpLocal && f.Protocol == "udp" {
			found = true
		}
	}
	if !found {
		t.Fatalf("static udp forward missing in %+v", list)
	}

	// A second stack trying to bind the same UDP port must fail.
	blocker, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	conflict := map[string]string{
		"udp:" + blocker.LocalAddr().String(): GuestIP + ":53",
	}
	if _, err := Start([6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}, conflict); err == nil {
		t.Fatal("want bind-conflict failure for a busy host port")
	} else if !strings.Contains(fmt.Sprint(err), "forwarder") && !strings.Contains(fmt.Sprint(err), "address already in use") {
		t.Fatalf("unexpected conflict error: %v", err)
	}
}
