package virtio

import (
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
	"time"

	"gantry/internal/netpol"
	"gantry/internal/vnet"

	"github.com/miekg/dns"
)

func TestNetWireRecordsAllowedAndBlockedTraffic(t *testing.T) {
	policy, err := netpol.Parse([]byte(`{"default":"deny","rules":[{"action":"allow","proto":"tcp","ports":"443"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	backend := &testPacketConn{rx: make(chan []byte, 1), tx: make(chan []byte, 1)}
	recorder := netpol.NewTrafficRecorder(filepath.Join(t.TempDir(), netpol.TrafficFileName))
	nic := &Net{conn: backend, policy: policy, traffic: recorder}

	allowed := tcpSYNFrame(t, "1.1.1.1", 443)
	if _, err := nic.writeFrame(allowed); err != nil {
		t.Fatal(err)
	}
	select {
	case <-backend.tx:
	default:
		t.Fatal("allowed frame did not reach backend")
	}
	blocked := tcpSYNFrame(t, "1.1.1.1", 80)
	if _, err := nic.writeFrame(blocked); err != nil {
		t.Fatal(err)
	}
	select {
	case <-backend.tx:
		t.Fatal("blocked frame reached backend")
	default:
	}

	snapshot := recorder.Snapshot()
	recorder.Close()
	if snapshot.TXPackets != 2 || snapshot.DroppedPackets != 1 || len(snapshot.Entries) != 2 {
		t.Fatalf("wire traffic snapshot = %#v", snapshot)
	}
}

// End-to-end through the production enforcement point: a QEMU-framed link
// with a policy attached, talking to the real embedded netstack. Verifies
// that an allowlisted DNS query resolves (and its answer is snooped into
// the policy's dynamic allow table) while an unlisted query never reaches
// the resolver.
func TestPolicyEnforcedOnWire(t *testing.T) {
	pol, err := netpol.Parse([]byte(`{"default": "deny", "allowDomains": ["debian.org"]}`))
	if err != nil {
		t.Fatal(err)
	}
	stack, err := vnet.Start([6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	raw, err := stack.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	conn := qemuFrameConn{conn: raw, pol: pol}

	// unlisted domain: query is dropped before the netstack ever sees it
	if _, err := conn.Write(dnsQueryFrame(t, "example.com")); err != nil {
		t.Fatal(err)
	}
	conn.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("dropped query still got %d bytes of answer", n)
	}

	// allowlisted domain: passes, resolves, and the answer is snooped.
	// The netstack may interleave ARP probes with the answer — skip anything
	// that isn't IPv4/UDP from port 53, answering ARP on the way.
	if _, err := conn.Write(dnsQueryFrame(t, "debian.org")); err != nil {
		t.Fatal(err)
	}
	conn.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var payload []byte
	for i := 0; i < 8 && payload == nil; i++ {
		n, err := conn.Read(buf)
		if err != nil {
			t.Skipf("no upstream DNS in this environment: %v", err)
		}
		frame := buf[:n]
		if et := binary.BigEndian.Uint16(frame[12:14]); et == 0x0806 {
			conn.Write(arpReply(frame)) // keep the link conversation going
			continue
		}
		if frame[14+9] == 17 && binary.BigEndian.Uint16(frame[14+20:14+22]) == 53 {
			payload = dnsResponsePayload(frame)
		}
	}
	if payload == nil {
		t.Fatal("no DNS answer among received frames")
	}
	var msg dns.Msg
	if err := msg.Unpack(payload); err != nil || !msg.Response {
		t.Fatalf("bad DNS response frame: %v", err)
	}
	if pol.DynamicSize() == 0 {
		t.Fatal("RX snoop did not learn any IPs from the allowlisted answer")
	}
}

func ipChecksum(h []byte) uint16 {
	sum := uint32(0)
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// dnsQueryFrame builds Ethernet/IPv4/UDP (UDP checksum 0 = none) to the
// gateway resolver.
func dnsQueryFrame(t *testing.T, name string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	payload, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(udp)))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], net.ParseIP("192.168.127.2").To4())
	copy(ip[16:20], net.ParseIP("192.168.127.1").To4())
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	frame := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd, 0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee, 0x08, 0x00}
	return append(append(frame, ip...), udp...)
}

// arpReply answers a who-has request with our guest MAC/IP.
func arpReply(req []byte) []byte {
	reply := append([]byte(nil), req...)
	copy(reply[0:6], req[6:12])   // dst = requester MAC
	copy(reply[6:12], req[22:28]) // src = our MAC (sender of the request target)
	binary.BigEndian.PutUint16(reply[20:22], 2)
	copy(reply[22:28], req[22:28]) // sender MAC = ours
	copy(reply[28:32], req[38:42]) // sender IP = requested target
	copy(reply[32:38], req[6:12])  // target MAC = requester
	copy(reply[38:42], req[28:32]) // target IP = requester IP
	return reply
}

// dnsResponsePayload extracts the UDP payload from an Ethernet/IPv4/UDP
// frame (sport 53).
func dnsResponsePayload(frame []byte) []byte {
	ihl := int(frame[14]&0x0f) * 4
	l4 := frame[14+ihl:]
	return l4[8:]
}

// The question that matters: with the DEFAULT policy (local net walled
// off), can the guest still reach the internet? Proven at TCP level: a SYN
// to a public IP:443 gets a SYN-ACK through policy + netstack NAT, while a
// SYN to a LAN address is dropped by the policy before the netstack sees
// it. DNS via the gateway resolver must also keep working.
func TestDefaultPolicyBlocksLocalKeepsInternet(t *testing.T) {
	pol := netpol.DefaultPolicy()
	stack, err := vnet.Start([6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	raw, err := stack.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn := qemuFrameConn{conn: raw, pol: pol}
	buf := make([]byte, 4096)

	// 1) LAN destination: SYN to a private IP is dropped (silence)
	if _, err := conn.Write(tcpSYNFrame(t, "192.168.1.1", 443)); err != nil {
		t.Fatal(err)
	}
	conn.conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("LAN SYN got %d bytes back — policy did not drop it", n)
	}

	// 2) public destination: SYN to 1.1.1.1:443 → SYN-ACK = internet egress
	if _, err := conn.Write(tcpSYNFrame(t, "1.1.1.1", 443)); err != nil {
		t.Fatal(err)
	}
	conn.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	gotSynAck := false
	for i := 0; i < 8 && !gotSynAck; i++ {
		n, err := conn.Read(buf)
		if err != nil {
			t.Skipf("no outbound internet in this environment: %v", err)
		}
		f := buf[:n]
		if binary.BigEndian.Uint16(f[12:14]) == 0x0806 {
			conn.Write(arpReply(f))
			continue
		}
		if f[14+9] == 6 && f[14+20+13]&0x12 == 0x12 { // TCP SYN|ACK
			gotSynAck = true
		}
	}
	if !gotSynAck {
		t.Fatal("no SYN-ACK from public internet — egress broken by default policy?")
	}

	// 3) gateway DNS still resolves (the apt/curl path starts here)
	if _, err := conn.Write(dnsQueryFrame(t, "debian.org")); err != nil {
		t.Fatal(err)
	}
	conn.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < 8; i++ {
		n, err := conn.Read(buf)
		if err != nil {
			t.Skipf("no upstream DNS in this environment: %v", err)
		}
		f := buf[:n]
		if binary.BigEndian.Uint16(f[12:14]) == 0x0806 {
			conn.Write(arpReply(f))
			continue
		}
		if f[14+9] == 17 && binary.BigEndian.Uint16(f[14+20:14+22]) == 53 {
			return // DNS answer arrived
		}
	}
	t.Fatal("gateway DNS did not answer under the default policy")
}

// tcpSYNFrame crafts an Ethernet/IPv4/TCP SYN with valid checksums.
func tcpSYNFrame(t *testing.T, dstIP string, dport uint16) []byte {
	t.Helper()
	src := net.ParseIP("192.168.127.2").To4()
	dst := net.ParseIP(dstIP).To4()
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], 1000) // seq
	tcp[12] = 5 << 4                           // data offset
	tcp[13] = 0x02                             // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	// TCP checksum over pseudo-header + segment
	pseudo := append(append(append([]byte{}, src...), dst...), 0, 6, 0, 20)
	binary.BigEndian.PutUint16(tcp[16:18], ipChecksum(append(pseudo, tcp...)))

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	frame := []byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd, 0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee, 0x08, 0x00}
	return append(append(frame, ip...), tcp...)
}
