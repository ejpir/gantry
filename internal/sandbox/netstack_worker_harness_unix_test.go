//go:build linux || darwin

package sandbox

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/networkworker"
	"github.com/ejpir/gantry/internal/sandbox/networker"
	"github.com/ejpir/gantry/internal/workerproto"
)

// startInProcessNetWorker runs a netstack worker in this process over a pair of
// pipes and attaches a supervisor to it. The daemon's shutdown ordering has to
// be exercised against a live worker, but spawning a child process would make
// the test depend on re-exec plumbing it is not testing.
func startInProcessNetWorker(t *testing.T) (*networker.Worker, net.Conn) {
	t.Helper()
	return startInProcessNetWorkerWithConfig(t, networkworker.Config{
		GuestMAC:    "5a:94:ef:e4:0c:ee",
		Policy:      json.RawMessage(`{"default":"allow"}`),
		Confinement: "off",
	})
}

func inProcessNetworkWorkerStart(t *testing.T) networkWorkerStart {
	t.Helper()
	return func(cfg networkworker.Config, _ string) (*networker.Worker, net.Conn, error) {
		worker, data := startInProcessNetWorkerWithConfig(t, cfg)
		return worker, data, nil
	}
}

func startInProcessNetWorkerWithConfig(t *testing.T, cfg networkworker.Config) (*networker.Worker, net.Conn) {
	t.Helper()
	// This harness exercises the supervisor topology in-process. Confining its
	// goroutine would confine the test process itself; process-level confinement
	// and re-exec are covered inside the networker package.
	cfg.Confinement = "off"
	cfg.ConfRoot = ""
	ctrlSup, ctrlWrk := net.Pipe()
	dataSup, dataWrk := net.Pipe()
	workerErr := make(chan error, 1)
	go func() { workerErr <- networkworker.Run(ctrlWrk, dataWrk) }()

	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	if err := workerproto.SendHandshake(ctrlSup, workerproto.RoleNet, nonce[:], cfg); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.WriteNonce(dataSup, nonce[:]); err != nil {
		t.Fatal(err)
	}
	var ack workerproto.Response
	_ = ctrlSup.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := workerproto.ReadMessage(ctrlSup, &ack); err != nil {
		t.Fatalf("worker ack: %v", err)
	}
	_ = ctrlSup.SetReadDeadline(time.Time{})
	if !ack.OK {
		t.Fatal("worker bootstrap refused")
	}

	w := networker.Attach(ctrlSup, dataSup)
	t.Cleanup(func() {
		_ = w.Close()
		select {
		case <-workerErr:
		case <-time.After(10 * time.Second):
			t.Error("worker did not exit after shutdown")
		}
	})
	return w, dataSup
}

// workerTestFrame builds one guest->host ethernet frame for the traffic path.
func workerTestFrame(t *testing.T, dstIP string, proto uint8, dport uint16) []byte {
	t.Helper()
	dst := net.ParseIP(dstIP).To4()
	src := net.ParseIP("192.168.127.2").To4()
	var l4 []byte
	switch proto {
	case 17: // udp
		l4 = make([]byte, 8)
		binary.BigEndian.PutUint16(l4[0:2], 12345)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		binary.BigEndian.PutUint16(l4[4:6], 8)
	case 6: // tcp
		l4 = make([]byte, 20)
		binary.BigEndian.PutUint16(l4[0:2], 12345)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		l4[12] = 5 << 4
		l4[13] = 0x02 // SYN
	default: // icmp
		l4 = make([]byte, 8)
	}
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(l4)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	frame := make([]byte, 0, 14+len(ip)+len(l4))
	gw, _ := net.ParseMAC("5a:94:ef:e4:0c:dd")
	guest, _ := net.ParseMAC("5a:94:ef:e4:0c:ee")
	frame = append(frame, gw...)
	frame = append(frame, guest...)
	frame = append(frame, 0x08, 0x00) // IPv4
	frame = append(frame, ip...)
	frame = append(frame, l4...)
	return frame
}
