package netpol

import (
	"bytes"
	"testing"

	"github.com/ejpir/gantry/internal/packetcapture"
)

func TestTrafficRecorderPacketCaptureIsOptIn(t *testing.T) {
	recorder := NewTrafficRecorder("")
	frame := bytes.Repeat([]byte{0x5a}, packetcapture.DefaultSnapLen+100)
	recorder.ObserveTX(frame, true)
	if got, err := recorder.Capture(packetcapture.Request{}); err != nil || len(got.Packets) != 0 {
		t.Fatalf("capture before start = %+v, %v", got, err)
	}

	if _, err := recorder.Capture(packetcapture.Request{Start: true}); err != nil {
		t.Fatal(err)
	}
	recorder.ObserveTX(frame, false)
	recorder.ObserveRX([]byte{1, 2, 3})
	got, err := recorder.Capture(packetcapture.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Packets) != 2 {
		t.Fatalf("captured packets = %d, want 2", len(got.Packets))
	}
	if got.Packets[0].Direction != packetcapture.TX || got.Packets[0].Allowed || got.Packets[0].Length != len(frame) || len(got.Packets[0].Data) != packetcapture.DefaultSnapLen {
		t.Fatalf("TX packet = %+v", got.Packets[0])
	}
	if got.Packets[1].Direction != packetcapture.RX || !got.Packets[1].Allowed {
		t.Fatalf("RX packet = %+v", got.Packets[1])
	}
}
