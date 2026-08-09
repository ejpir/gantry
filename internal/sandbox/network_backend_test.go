package sandbox

import (
	"errors"
	"testing"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/vnet"
)

type policyBackendStub struct {
	policy    *netpol.Policy
	failNext  error
	failAt    int
	failAtErr error
	calls     int
}

func (b *policyBackendStub) Publish(string, string, string) error { return nil }
func (b *policyBackendStub) Unpublish(string, string) error       { return nil }
func (b *policyBackendStub) Forwards() ([]vnet.Forward, error)    { return nil, nil }
func (b *policyBackendStub) SetPolicy(policy *netpol.Policy) error {
	b.calls++
	if b.failAt == b.calls {
		return b.failAtErr
	}
	if b.failNext != nil {
		err := b.failNext
		b.failNext = nil
		return err
	}
	b.policy = mustPolicySnapshot(policy)
	return nil
}

type policyPusherStub struct {
	policy    *netpol.Policy
	failNext  error
	failAt    int
	failAtErr error
	calls     int
	closed    bool
}

func (p *policyPusherStub) SetPolicy(policy *netpol.Policy) error {
	p.calls++
	if p.failAt == p.calls {
		return p.failAtErr
	}
	if p.failNext != nil {
		err := p.failNext
		p.failNext = nil
		return err
	}
	p.policy = mustPolicySnapshot(policy)
	return nil
}

func (p *policyPusherStub) Close() error {
	p.closed = true
	return nil
}

func mustPolicySnapshot(policy *netpol.Policy) *netpol.Policy {
	copy, err := cloneNetworkPolicy(policy)
	if err != nil {
		panic(err)
	}
	return copy
}

func mustTestPolicy(t *testing.T, raw string) *netpol.Policy {
	t.Helper()
	p, err := netpol.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func samePolicy(t *testing.T, got, want *netpol.Policy) bool {
	t.Helper()
	gotRaw, err := netpol.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	wantRaw, err := netpol.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	return string(gotRaw) == string(wantRaw)
}

func TestVMMPolicyBackendFailureLeavesPreviousPolicy(t *testing.T) {
	old := mustTestPolicy(t, `{"default":"deny"}`)
	next := mustTestPolicy(t, `{"default":"allow","allowLocal":true}`)

	t.Run("worker push fails", func(t *testing.T) {
		local := &policyBackendStub{policy: mustPolicySnapshot(old)}
		worker := &policyPusherStub{policy: mustPolicySnapshot(old), failNext: errors.New("worker unavailable")}
		fanout, err := newVMMPolicyBackend(local, worker, old)
		if err != nil {
			t.Fatal(err)
		}
		if err := fanout.SetPolicy(next); err == nil {
			t.Fatal("worker failure reported success")
		}
		if local.calls != 0 {
			t.Fatalf("local mirror mutated before worker confirmation (%d calls)", local.calls)
		}
		if !samePolicy(t, local.policy, old) || !samePolicy(t, worker.policy, old) {
			t.Fatal("failed fan-out changed an enforced policy")
		}
		if !worker.closed {
			t.Fatal("unconfirmed worker update did not fail closed")
		}
	})

	t.Run("local mirror fails", func(t *testing.T) {
		local := &policyBackendStub{policy: mustPolicySnapshot(old), failNext: errors.New("local failure")}
		worker := &policyPusherStub{policy: mustPolicySnapshot(old)}
		fanout, err := newVMMPolicyBackend(local, worker, old)
		if err != nil {
			t.Fatal(err)
		}
		if err := fanout.SetPolicy(next); err == nil {
			t.Fatal("local failure reported success")
		}
		if worker.calls != 2 {
			t.Fatalf("worker calls = %d, want apply + rollback", worker.calls)
		}
		if !samePolicy(t, local.policy, old) || !samePolicy(t, worker.policy, old) {
			t.Fatal("rollback did not restore the previous policy")
		}
		if worker.closed {
			t.Fatal("confirmed rollback unnecessarily stopped the worker")
		}
	})

	t.Run("failed rollback stops ambiguous worker", func(t *testing.T) {
		local := &policyBackendStub{policy: mustPolicySnapshot(old), failNext: errors.New("local failure")}
		worker := &policyPusherStub{
			policy: mustPolicySnapshot(old), failAt: 2, failAtErr: errors.New("rollback response lost"),
		}
		fanout, err := newVMMPolicyBackend(local, worker, old)
		if err != nil {
			t.Fatal(err)
		}
		if err := fanout.SetPolicy(next); err == nil {
			t.Fatal("failed rollback reported success")
		}
		if !worker.closed {
			t.Fatal("ambiguous VMM policy state did not stop the worker")
		}
	})

	t.Run("success", func(t *testing.T) {
		local := &policyBackendStub{policy: mustPolicySnapshot(old)}
		worker := &policyPusherStub{policy: mustPolicySnapshot(old)}
		fanout, err := newVMMPolicyBackend(local, worker, old)
		if err != nil {
			t.Fatal(err)
		}
		if err := fanout.SetPolicy(next); err != nil {
			t.Fatal(err)
		}
		if !samePolicy(t, local.policy, next) || !samePolicy(t, worker.policy, next) {
			t.Fatal("successful fan-out did not converge")
		}
	})
}
