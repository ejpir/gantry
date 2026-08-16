package packetcapture

import "testing"

func TestRecorderIsOptInAndBounded(t *testing.T) {
	r := NewRecorder(2, 8, 4)
	r.ObserveTX([]byte{1, 2, 3}, true)
	if got := r.Apply(Request{}); len(got.Packets) != 0 || got.Active {
		t.Fatalf("capture before start = %+v", got)
	}
	r.Apply(Request{Start: true})
	r.ObserveTX([]byte{1, 2, 3, 4, 5}, false)
	r.ObserveRX([]byte{6, 7, 8, 9})
	r.ObserveTX([]byte{10, 11, 12, 13}, true)
	got := r.Apply(Request{})
	if len(got.Packets) != 2 || got.Evicted != 1 {
		t.Fatalf("bounded snapshot = %+v", got)
	}
	if got.Packets[0].Sequence != 2 || got.Packets[1].Sequence != 3 {
		t.Fatalf("retained sequences = %d,%d", got.Packets[0].Sequence, got.Packets[1].Sequence)
	}
	if got.Packets[0].Direction != RX || len(got.Packets[0].Data) != 4 {
		t.Fatalf("retained packet = %+v", got.Packets[0])
	}
}

func TestRecorderCursorClearAndStop(t *testing.T) {
	r := NewRecorder(8, 1024, 64)
	r.Apply(Request{Start: true})
	r.ObserveTX([]byte{1}, true)
	r.ObserveRX([]byte{2})
	got := r.Apply(Request{After: 1})
	if len(got.Packets) != 1 || got.Packets[0].Sequence != 2 {
		t.Fatalf("cursor snapshot = %+v", got)
	}
	got = r.Apply(Request{Clear: true})
	if len(got.Packets) != 0 || !got.Active || got.Next != 0 || got.Latest != 2 || got.Evicted != 0 {
		t.Fatalf("clear snapshot = %+v", got)
	}
	r.ObserveTX([]byte{3}, true)
	got = r.Apply(Request{Stop: true})
	if got.Active || len(got.Packets) != 0 {
		t.Fatalf("stop snapshot = %+v", got)
	}
}
