package vmm

import (
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/virtio"
)

type nilablePolicy struct{}

func (*nilablePolicy) MatchTX([]byte) bool { return true }
func (*nilablePolicy) ObserveRX([]byte)    {}

// An egress boundary handed a typed nil is worse than one handed nothing:
// the device's `policy != nil` guard passes and every frame either panics
// the VMM or slips past a policy that is not there. Prepare refuses it.
func TestCheckNilInterfaceRejectsTypedNil(t *testing.T) {
	var absent *nilablePolicy
	err := checkNilInterface("NetPolicy", virtio.PacketPolicy(absent))
	if err == nil {
		t.Fatal("typed-nil PacketPolicy accepted")
	}
	if !strings.Contains(err.Error(), "opts.NetPolicy holds a nil") {
		t.Fatalf("error = %v", err)
	}
}

func TestCheckNilInterfaceAcceptsAbsentAndPresent(t *testing.T) {
	var absent virtio.PacketPolicy
	if err := checkNilInterface("NetPolicy", absent); err != nil {
		t.Fatalf("nil interface rejected: %v", err)
	}
	if err := checkNilInterface("NetPolicy", virtio.PacketPolicy(&nilablePolicy{})); err != nil {
		t.Fatalf("live policy rejected: %v", err)
	}
}
