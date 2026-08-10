package networkworker

import (
	"fmt"
	"testing"
)

func TestPortTransactionReplayAndCacheBound(t *testing.T) {
	var workerState state
	mutation := portMutation{
		operation: OpPortPublish,
		proto:     "tcp",
		local:     "127.0.0.1:18080",
		remote:    "192.168.127.2:80",
	}
	calls := 0
	apply := func() error {
		calls++
		return nil
	}
	first, err := workerState.applyPortMutation("same-transaction", mutation, apply)
	if err != nil || first.State != PortStateApplied {
		t.Fatalf("first mutation = %+v, err=%v", first, err)
	}
	replayed, err := workerState.applyPortMutation("same-transaction", mutation, apply)
	if err != nil || replayed != first || calls != 1 {
		t.Fatalf("replayed mutation = %+v, err=%v, apply calls=%d", replayed, err, calls)
	}
	changed := mutation
	changed.remote = "192.168.127.2:81"
	if _, err := workerState.applyPortMutation("same-transaction", changed, apply); err == nil {
		t.Fatal("transaction ID reuse with different content succeeded")
	}
	if calls != 1 {
		t.Fatalf("reused transaction invoked mutation %d times", calls)
	}

	for i := 0; i < maxPortTransactions+10; i++ {
		id := fmt.Sprintf("transaction-%d", i)
		workerState.rememberPortTransaction(id, portTransaction{
			mutation: mutation,
			response: PortStatusResponse{Transaction: id, State: PortStateApplied},
		})
	}
	if len(workerState.portTxns) != maxPortTransactions {
		t.Fatalf("transaction cache retained %d entries, want %d", len(workerState.portTxns), maxPortTransactions)
	}
	if _, retained := workerState.portTxns["transaction-0"]; retained {
		t.Fatal("transaction cache did not evict its oldest entry")
	}
	if _, retained := workerState.portTxns[fmt.Sprintf("transaction-%d", maxPortTransactions+9)]; !retained {
		t.Fatal("transaction cache evicted its newest entry")
	}
}
