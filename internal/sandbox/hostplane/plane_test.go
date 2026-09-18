package hostplane

import (
	"reflect"
	"testing"
)

func TestPlaneClosesResourcesInReverseAcquisitionOrderOnce(t *testing.T) {
	var order []string
	record := func(value string) func() error {
		return func() error { order = append(order, value); return nil }
	}
	var plane Plane[string, string, string, string, string, string, string]
	plane.SetLock(record("lock"))
	plane.SetConfig("config")
	plane.SetAudit("audit")
	plane.SetConsole("console", record("console"))
	plane.SetConsoleLog(record("console-log"))
	plane.SetNetwork("network", record("network-backend"), func() { order = append(order, "network") })
	plane.SetShares("shares", record("shares"))
	plane.SetPorts("ports")
	plane.SetTransactions("transactions")

	if err := plane.CloseShutdownNetwork(); err != nil {
		t.Fatal(err)
	}
	if err := plane.Close(); err != nil {
		t.Fatal(err)
	}
	if err := plane.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{"network-backend", "shares", "network", "console", "console-log", "lock"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("close order = %v, want %v", order, want)
	}
	if plane.Config() != "config" || plane.Audit() != "audit" || plane.Ports() != "ports" || plane.Transactions() != "transactions" {
		t.Fatal("owned non-closing resources changed during shutdown")
	}
}
