package dashboardsvc

import (
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/netpol"
	"testing"
)

func TestRuleRemovalRejectsStaleOrdinalRatherThanDeletingAnotherDestination(t *testing.T) {
	policy, err := netpol.WithRule(netpol.DefaultPolicy(), netpol.RuleSpec{Action: "allow", CIDR: "10.10.0.0/24", Protocol: "tcp", Ports: "443"})
	if err != nil {
		t.Fatal(err)
	}
	var row dashboardapi.Rule
	for _, summary := range policy.RuleSummaries() {
		if summary.Source == "rule 1" {
			row = dashboardapi.Rule{Source: summary.Source, Action: summary.Action, Target: summary.Target, Proto: summary.Protocol, Ports: summary.Ports}
		}
	}
	changed, err := netpol.WithoutRule(policy, 0)
	if err != nil {
		t.Fatal(err)
	}
	changed, err = netpol.WithRule(changed, netpol.RuleSpec{Action: "deny", CIDR: "10.20.0.0/24", Protocol: "udp", Ports: "53"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := removeSelectedRule(changed, row, 0); err == nil {
		t.Fatal("stale row deleted a different rule")
	}
	if len(changed.Rules) != 1 {
		t.Fatal("rejected mutation changed policy")
	}
	result, err := removeSelectedRule(policy, row, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rules) != 0 {
		t.Fatal("unchanged selected rule was not removed")
	}
}
