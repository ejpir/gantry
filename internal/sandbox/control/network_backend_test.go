package control

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/vnet"
)

type localNetworkStackStub struct {
	mu                 sync.Mutex
	forwards           []vnet.Forward
	publishStarted     chan struct{}
	releasePublish     chan struct{}
	publishStartOnce   sync.Once
	unpublishStarted   chan struct{}
	releaseUnpublish   chan struct{}
	unpublishStartOnce sync.Once
}

func (s *localNetworkStackStub) Publish(proto, local, remote string) error {
	if s.publishStarted != nil {
		s.publishStartOnce.Do(func() { close(s.publishStarted) })
	}
	if s.releasePublish != nil {
		<-s.releasePublish
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forwards = append(s.forwards, vnet.Forward{Local: local, Remote: remote, Protocol: proto})
	return nil
}

func (s *localNetworkStackStub) Unpublish(proto, local string) error {
	if s.unpublishStarted != nil {
		s.unpublishStartOnce.Do(func() { close(s.unpublishStarted) })
	}
	if s.releaseUnpublish != nil {
		<-s.releaseUnpublish
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, forward := range s.forwards {
		if forward.Protocol == proto && forward.Local == local {
			s.forwards = append(s.forwards[:i], s.forwards[i+1:]...)
			break
		}
	}
	return nil
}

func (s *localNetworkStackStub) Forwards() ([]vnet.Forward, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]vnet.Forward(nil), s.forwards...), nil
}

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
	copy, err := ClonePolicy(policy)
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

func TestPolicyMirrorChangesOnlyAfterSplitBackendAcceptsPolicy(t *testing.T) {
	old := mustTestPolicy(t, `{"default":"deny","allowDomains":["github.com"]}`)
	next := mustTestPolicy(t, `{"default":"deny","allowDomains":["gitlab.com"]}`)
	split := &policyBackendStub{policy: mustPolicySnapshot(old), failNext: errors.New("worker unavailable")}
	mirror, err := NewPolicyMirrorBackend(split, old)
	if err != nil {
		t.Fatal(err)
	}
	if err := mirror.SetPolicy(next); err == nil {
		t.Fatal("split worker failure reported success")
	}
	if !old.DomainAllowed("github.com") || old.DomainAllowed("gitlab.com") {
		t.Fatal("failed split update changed the supervisor policy mirror")
	}
	if err := mirror.SetPolicy(next); err != nil {
		t.Fatal(err)
	}
	if old.DomainAllowed("github.com") || !old.DomainAllowed("gitlab.com") {
		t.Fatal("successful split update did not change the supervisor policy mirror")
	}
}

func TestLocalBackendRejectsUDPWithoutGatewayReplyPolicy(t *testing.T) {
	// A nil stack makes the ordering assertion explicit: policy validation must
	// reject before any listener operation is attempted.
	denied := NewLocalBackend(nil, netpol.DefaultPolicy())
	if err := denied.Publish("udp", "127.0.0.1:48081", vnet.GuestIP+":18081"); err == nil {
		t.Fatal("default local-network wall accepted a live UDP forward")
	} else if !strings.Contains(err.Error(), "gateway reply port") {
		t.Fatalf("live UDP policy error = %v", err)
	}
}

func TestLocalBackendRejectsPolicyThatBreaksActiveUDPForward(t *testing.T) {
	live := mustTestPolicy(t, `{"default":"allow","allowLocal":true}`)
	stack := &localNetworkStackStub{forwards: []vnet.Forward{{
		Local: "127.0.0.1:48081", Remote: vnet.GuestIP + ":18081", Protocol: "udp",
	}}}
	backend := &localBackend{stack: stack, live: live}

	if err := backend.SetPolicy(netpol.DefaultPolicy()); err == nil {
		t.Fatal("policy tightening succeeded while a UDP forward was active")
	} else if !strings.Contains(err.Error(), "gateway reply port") {
		t.Fatalf("policy tightening error = %v", err)
	}
	if err := netpol.ValidateUDPPortPublishing(live); err != nil {
		t.Fatalf("rejected update changed the live policy: %v", err)
	}

	if err := backend.Unpublish("udp", "127.0.0.1:48081"); err != nil {
		t.Fatal(err)
	}
	if err := backend.SetPolicy(netpol.DefaultPolicy()); err != nil {
		t.Fatalf("policy tightening after UDP unpublish: %v", err)
	}
}

func TestLocalBackendSerializesPublishWithPolicyUpdate(t *testing.T) {
	live := mustTestPolicy(t, `{"default":"allow","allowLocal":true}`)
	stack := &localNetworkStackStub{
		publishStarted: make(chan struct{}),
		releasePublish: make(chan struct{}),
	}
	backend := &localBackend{stack: stack, live: live}

	publishDone := make(chan error, 1)
	go func() {
		publishDone <- backend.Publish("udp", "127.0.0.1:48081", vnet.GuestIP+":18081")
	}()
	select {
	case <-stack.publishStarted:
	case <-time.After(time.Second):
		t.Fatal("UDP publish did not reach the stack")
	}

	policyDone := make(chan error, 1)
	go func() { policyDone <- backend.SetPolicy(netpol.DefaultPolicy()) }()
	select {
	case err := <-policyDone:
		t.Fatalf("policy update overtook an in-flight UDP publish: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(stack.releasePublish)
	if err := <-publishDone; err != nil {
		t.Fatal(err)
	}
	if err := <-policyDone; err == nil {
		t.Fatal("policy update ignored the newly active UDP forward")
	} else if !strings.Contains(err.Error(), "gateway reply port") {
		t.Fatalf("serialized policy update error = %v", err)
	}
}

func TestVMMPolicyBackendFailureLeavesPreviousPolicy(t *testing.T) {
	old := mustTestPolicy(t, `{"default":"deny"}`)
	next := mustTestPolicy(t, `{"default":"allow","allowLocal":true}`)

	t.Run("worker push fails", func(t *testing.T) {
		local := &policyBackendStub{policy: mustPolicySnapshot(old)}
		worker := &policyPusherStub{policy: mustPolicySnapshot(old), failNext: errors.New("worker unavailable")}
		fanout, err := NewVMMPolicyBackend(local, worker, old)
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
		fanout, err := NewVMMPolicyBackend(local, worker, old)
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
		fanout, err := NewVMMPolicyBackend(local, worker, old)
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
		fanout, err := NewVMMPolicyBackend(local, worker, old)
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
