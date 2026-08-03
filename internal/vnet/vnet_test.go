package vnet

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// Start the embedded stack, connect over the QEMU-framed link, and resolve
// the gateway's MAC with a real ARP exchange. Covers: netstack up, switch
// delivery both ways, our framing, and the ARP service the guest's DHCP
// depends on first.
func TestEmbeddedStackARP(t *testing.T) {
	guestMAC := [6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}
	stack, err := Start(guestMAC, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	conn, err := stack.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Ethernet: broadcast ARP request, who-has 192.168.127.1 tell 192.168.127.2
	gwIP := net.ParseIP(GatewayIP).To4()
	guestIP := net.ParseIP(GuestIP).To4()
	frame := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst: broadcast
		guestMAC[0], guestMAC[1], guestMAC[2], guestMAC[3], guestMAC[4], guestMAC[5],
		0x08, 0x06, // ARP
		0x00, 0x01, // htype: ethernet
		0x08, 0x00, // ptype: IPv4
		0x06, 0x04, // hlen, plen
		0x00, 0x01, // op: request
		guestMAC[0], guestMAC[1], guestMAC[2], guestMAC[3], guestMAC[4], guestMAC[5],
		guestIP[0], guestIP[1], guestIP[2], guestIP[3],
		0, 0, 0, 0, 0, 0, // target MAC: any
		gwIP[0], gwIP[1], gwIP[2], gwIP[3],
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(frame)))
	if _, err := conn.Write(append(hdr[:], frame...)); err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var rhdr [4]byte
	if _, err := readFull(conn, rhdr[:]); err != nil {
		t.Fatal("no ARP reply:", err)
	}
	n := binary.BigEndian.Uint32(rhdr[:])
	if n < 42 || n > 2048 {
		t.Fatalf("bad reply frame len %d", n)
	}
	reply := make([]byte, n)
	if _, err := readFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply[:6]) != string(guestMAC[:]) {
		t.Fatalf("reply dst %x, want guest MAC", reply[:6])
	}
	if reply[12] != 0x08 || reply[13] != 0x06 || reply[21] != 0x02 {
		t.Fatalf("not an ARP reply: ethertype %x op %d", reply[12:14], reply[21])
	}
	senderMAC := net.HardwareAddr(reply[22:28]).String()
	if senderMAC != GatewayMAC {
		t.Fatalf("gateway MAC %s, want %s", senderMAC, GatewayMAC)
	}
	if string(reply[28:32]) != string(gwIP) {
		t.Fatalf("sender IP %v, want %v", reply[28:32], gwIP)
	}
}

func readFull(c net.Conn, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := c.Read(p[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
