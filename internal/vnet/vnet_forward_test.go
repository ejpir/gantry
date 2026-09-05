package vnet

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
)

// A published TCP connection is dialed by the embedded stack from the virtual
// gateway. Capture that real SYN on the QEMU link and verify default policy
// admits only its exact reverse SYN-ACK after trusted ingress observation.
func TestPublishedTCPReturnAcceptedByPolicy(t *testing.T) {
	guestMAC := [6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}
	stack, err := Start(guestMAC, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	link, err := stack.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = link.Close() }()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	local := listener.Addr().String()
	_ = listener.Close()
	const guestPort = 18080
	if err := stack.Publish("tcp", local, fmt.Sprintf("%s:%d", GuestIP, guestPort)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stack.Unpublish("tcp", local) }()
	host, err := net.DialTimeout("tcp", local, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()
	_, _ = host.Write([]byte("GET / HTTP/1.0\r\n\r\n"))

	_ = link.SetDeadline(time.Now().Add(5 * time.Second))
	var syn []byte
	for syn == nil {
		frame, err := readQEMUFrame(link)
		if err != nil {
			t.Fatal("published connection did not reach guest link:", err)
		}
		if isARPRequestFor(frame, GuestIP) {
			if err := writeQEMUFrame(link, arpReply(frame, guestMAC)); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if isTCPInitialSYN(frame, GuestIP, guestPort) {
			syn = frame
		}
	}

	reply := reverseTCPFrame(syn, 0x12) // SYN|ACK
	policy := netpol.DefaultPolicy()
	if policy.MatchTX(reply) {
		t.Fatal("reverse tuple passed before trusted published-flow ingress")
	}
	policy.ObserveRX(syn)
	if !policy.MatchTX(reply) {
		t.Fatal("real published-flow SYN-ACK was denied by default policy")
	}
}

func readQEMUFrame(conn net.Conn) ([]byte, error) {
	var header [4]byte
	if _, err := readFull(conn, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > 64*1024 {
		return nil, fmt.Errorf("invalid QEMU frame size %d", size)
	}
	frame := make([]byte, size)
	_, err := readFull(conn, frame)
	return frame, err
}

func writeQEMUFrame(conn net.Conn, frame []byte) error {
	packet := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(packet[:4], uint32(len(frame)))
	copy(packet[4:], frame)
	_, err := conn.Write(packet)
	return err
}

func isARPRequestFor(frame []byte, target string) bool {
	return len(frame) >= 42 && binary.BigEndian.Uint16(frame[12:14]) == 0x0806 &&
		binary.BigEndian.Uint16(frame[20:22]) == 1 &&
		net.IP(frame[38:42]).Equal(net.ParseIP(target))
}

func arpReply(request []byte, guestMAC [6]byte) []byte {
	reply := make([]byte, 42)
	copy(reply[0:6], request[6:12])
	copy(reply[6:12], guestMAC[:])
	copy(reply[12:20], request[12:20])
	binary.BigEndian.PutUint16(reply[20:22], 2)
	copy(reply[22:28], guestMAC[:])
	copy(reply[28:32], request[38:42])
	copy(reply[32:38], request[22:28])
	copy(reply[38:42], request[28:32])
	return reply
}

func isTCPInitialSYN(frame []byte, destination string, port uint16) bool {
	if len(frame) < 14+20+20 || binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return false
	}
	ip := frame[14:]
	ihl := int(ip[0]&0x0f) * 4
	if ip[0]>>4 != 4 || ihl < 20 || len(ip) < ihl+20 || ip[9] != 6 ||
		!net.IP(ip[16:20]).Equal(net.ParseIP(destination)) {
		return false
	}
	tcp := ip[ihl:]
	return binary.BigEndian.Uint16(tcp[2:4]) == port && tcp[13]&0x02 != 0 && tcp[13]&0x10 == 0
}

func reverseTCPFrame(frame []byte, flags byte) []byte {
	reply := append([]byte(nil), frame...)
	copy(reply[0:6], frame[6:12])
	copy(reply[6:12], frame[0:6])
	ip := reply[14:]
	ihl := int(ip[0]&0x0f) * 4
	sourceIP := append([]byte(nil), ip[12:16]...)
	copy(ip[12:16], ip[16:20])
	copy(ip[16:20], sourceIP)
	tcp := ip[ihl:]
	sourcePort := append([]byte(nil), tcp[0:2]...)
	copy(tcp[0:2], tcp[2:4])
	copy(tcp[2:4], sourcePort)
	tcp[13] = flags
	return reply
}

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
	_ = l.Close()

	if err := stack.Publish("tcp", local, GuestIP+":80"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// The host listener is live: a connect succeeds at TCP level even
	// though the guest side has nothing to answer.
	probe, err := net.Dial("tcp", local)
	if err != nil {
		t.Fatalf("host listener not accepting: %v", err)
	}
	_ = probe.Close()

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
	_ = pc.Close()

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
	defer func() { _ = blocker.Close() }()
	conflict := map[string]string{
		"udp:" + blocker.LocalAddr().String(): GuestIP + ":53",
	}
	if _, err := Start([6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}, conflict); err == nil {
		t.Fatal("want bind-conflict failure for a busy host port")
	} else {
		// The bind error wording is platform-specific ("address already in
		// use" vs Windows' "Only one usage of each socket address..."), so
		// assert on the stable part: the busy port must appear in the
		// failure.
		_, port, splitErr := net.SplitHostPort(blocker.LocalAddr().String())
		if splitErr != nil {
			t.Fatal(splitErr)
		}
		if !strings.Contains(fmt.Sprint(err), ":"+port) {
			t.Fatalf("conflict error %q does not reference busy port %s", err, port)
		}
	}
}
