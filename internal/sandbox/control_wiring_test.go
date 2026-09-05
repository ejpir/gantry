package sandbox

// Broker wiring for the control-plane managers. The managers themselves are
// tested in the control package; these cover the daemon's dispatch to them.
// Share wiring needs a mounted hub and lives in control_wiring_unix_test.go.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/control"
	"github.com/ejpir/gantry/internal/vnet"
)

type wiringNetworkBackend struct {
	live *netpol.Policy
}

func (*wiringNetworkBackend) Publish(string, string, string) error { return nil }
func (*wiringNetworkBackend) Unpublish(string, string) error       { return nil }
func (*wiringNetworkBackend) Forwards() ([]vnet.Forward, error)    { return nil, nil }
func (b *wiringNetworkBackend) SetPolicy(policy *netpol.Policy) error {
	return b.live.Replace(policy)
}

func TestBrokerNetworkPolicyControl(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, config.RunConfig{Net: true})
	policyPath := filepath.Join(dir, "deny.json")
	if err := os.WriteFile(policyPath, []byte(`{"default":"deny"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	live := netpol.DefaultPolicy()
	br := &broker{
		netPolicy: control.NewNetworkPolicyManager(store, &wiringNetworkBackend{live: live}, live),
		sessions:  map[string]chan struct{}{},
	}
	request := `{"op":"netpolicy.set","id":"policy","net_policy":{"path":` + strconv.Quote(policyPath) + `}}` + "\n"
	if got := brokerPipe(t, br, request); !strings.Contains(got, `"ok":true`) || !strings.Contains(got, `"state":"active"`) || !strings.Contains(got, `"rules"`) {
		t.Fatalf("set response = %s", got)
	}
	if got := brokerPipe(t, br, `{"op":"netpolicy.get","id":"policy-show"}`+"\n"); !strings.Contains(got, `"ok":true`) || !strings.Contains(got, "default deny") {
		t.Fatalf("show response = %s", got)
	}
}
