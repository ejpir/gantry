package sandbox

// Broker wiring and CLI rendering for the control-plane managers. The managers
// themselves are tested in the control package; these cover the daemon's
// dispatch to them and the command output built from their results.

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

func TestBrokerNetworkPolicyControl(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, config.RunConfig{Net: true})
	policyPath := filepath.Join(dir, "deny.json")
	if err := os.WriteFile(policyPath, []byte(`{"default":"deny"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	live := netpol.DefaultPolicy()
	br := &broker{
		netPolicy: control.NewNetworkPolicyManager(store, control.NewLocalBackend(&vnet.Stack{}, live), live),
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

func TestBrokerShareControl(t *testing.T) {
	manager, _ := newTestShareManager(t)
	br := &broker{sessions: map[string]chan struct{}{}, shares: manager}
	dir := t.TempDir()
	resp := brokerPipe(t, br, `{"op":"share.add","id":"s1","share":{"spec":"code=`+dir+`,ro","persistent":false}}`+"\n")
	if !strings.Contains(resp, `"ok":true`) || !strings.Contains(resp, `"tag":"code"`) {
		t.Fatalf("add resp = %s", resp)
	}
	resp = brokerPipe(t, br, `{"op":"share.list","id":"s2","share":{"persistent":true}}`+"\n")
	if !strings.Contains(resp, `"ctrPath":"/host/code"`) {
		t.Fatalf("list resp = %s", resp)
	}
	resp = brokerPipe(t, br, `{"op":"share.remove","id":"s3","share":{"tag":"code","persistent":false,"force":true}}`+"\n")
	if !strings.Contains(resp, `"ok":true`) {
		t.Fatalf("remove resp = %s", resp)
	}
}
