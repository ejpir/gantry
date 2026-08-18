//go:build linux || darwin

package networker

import (
	"testing"

	"github.com/ejpir/gantry/internal/netpol"
)

func mustTestPolicy(t *testing.T, raw string) *netpol.Policy {
	t.Helper()
	p, err := netpol.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
