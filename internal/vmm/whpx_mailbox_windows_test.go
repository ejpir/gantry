//go:build windows

package vmm

import (
	"bytes"
	"testing"
)

func TestWHPXMailboxRoundTrip(t *testing.T) {
	files, err := NewWHPXMailboxFiles(2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = files.Close() }()

	broker, err := mapWHPXMailboxView(files.Mapping, files.RequestEvent, files.ReplyEvents, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = broker.close() }()
	target, err := mapWHPXMailboxView(files.Mapping, files.RequestEvent, files.ReplyEvents, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.close() }()

	context := bytes.Repeat([]byte{0x5a}, whvExitContextSize)
	exit := whpxBrokerExit{ID: 17, VCPU: 1, Context: context, GPRs: make([]uint64, 16)}
	exit.GPRs[3] = 0x1234
	result := make(chan whpxBrokerReply, 1)
	errCh := make(chan error, 1)
	go func() {
		if err := broker.sendExit(exit); err != nil {
			errCh <- err
			return
		}
		reply, err := broker.waitReply(exit.VCPU, exit.ID)
		if err != nil {
			errCh <- err
			return
		}
		result <- reply
	}()

	if err := target.waitRequest(); err != nil {
		t.Fatal(err)
	}
	exits, err := target.claimRequests()
	if err != nil {
		t.Fatal(err)
	}
	if len(exits) != 1 || exits[0].ID != exit.ID || exits[0].VCPU != exit.VCPU ||
		!bytes.Equal(exits[0].Context, context) || exits[0].GPRs[3] != 0x1234 {
		t.Fatalf("mailbox request mismatch: %+v", exits)
	}
	want := whpxBrokerReply{
		ID: exit.ID, RegisterNames: []uint32{whvRegRax, whvRegRip},
		RegisterValues: []uint64{0xbeef, 0xfeed},
	}
	if err := target.respond(exit.VCPU, want); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		t.Fatal(err)
	case got := <-result:
		if got.ID != want.ID || got.Stop || got.Error != "" ||
			len(got.RegisterNames) != 2 || got.RegisterNames[0] != whvRegRax || got.RegisterNames[1] != whvRegRip ||
			got.RegisterValues[0] != 0xbeef || got.RegisterValues[1] != 0xfeed {
			t.Fatalf("mailbox reply mismatch: %+v", got)
		}
	}
}

func TestWHPXMailboxRejectsBusySlot(t *testing.T) {
	files, err := NewWHPXMailboxFiles(1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = files.Close() }()
	view, err := mapWHPXMailboxView(files.Mapping, files.RequestEvent, files.ReplyEvents, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = view.close() }()

	exit := whpxBrokerExit{ID: 1, Context: make([]byte, whvExitContextSize)}
	if err := view.sendExit(exit); err != nil {
		t.Fatal(err)
	}
	exit.ID++
	if err := view.sendExit(exit); err == nil {
		t.Fatal("second request unexpectedly replaced an outstanding exit")
	}
}

func TestValidateWHPXBrokerConfigRejectsBadToken(t *testing.T) {
	config := WHPXBrokerConfig{MemSize: MinMemoryBytes, VCPUs: 1, PeerToken: "short"}
	if err := validateWHPXBrokerConfig(config); err == nil {
		t.Fatal("short peer token was accepted")
	}
}
