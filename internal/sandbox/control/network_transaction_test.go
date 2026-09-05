package control

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/vnet"
)

type blockedPolicyBackend struct {
	NetworkBackend
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockedPolicyBackend) SetPolicy(policy *netpol.Policy) error {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return b.NetworkBackend.SetPolicy(policy)
}

func TestNetworkTransactionSerializesPolicyRollbackWithUDPPublish(t *testing.T) {
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, config.RunConfig{Net: true})
	policyPath := filepath.Join(dir, "allow-local.json")
	if err := os.WriteFile(policyPath, []byte(`{"default":"allow","allowLocal":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	persistErr := errors.New("injected policy persistence failure")
	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	var writeOnce sync.Once
	store.SetWriter(func(string, []byte, os.FileMode) error {
		writeOnce.Do(func() { close(writeStarted) })
		<-releaseWrite
		return persistErr
	})

	live := netpol.DefaultPolicy()
	stack := &localNetworkStackStub{publishStarted: make(chan struct{})}
	backend := &localBackend{stack: stack, live: live}
	transactions := NewNetworkTransactionCoordinator()
	policies := NewNetworkPolicyManagerWithCoordinator(store, backend, live, transactions)
	ports := NewPortManagerWithCoordinator(store, backend, transactions)

	policyDone := make(chan error, 1)
	go func() {
		_, err := policies.Set(policyPath, false)
		policyDone <- err
	}()
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("policy transaction did not reach persistence")
	}
	if err := netpol.ValidateUDPPortPublishing(live); err != nil {
		t.Fatalf("candidate permissive policy was not applied before persistence: %v", err)
	}

	publishAttempted := make(chan struct{})
	publishDone := make(chan error, 1)
	go func() {
		close(publishAttempted)
		_, err := ports.Publish("127.0.0.1:48101:18081/udp", false)
		publishDone <- err
	}()
	<-publishAttempted
	select {
	case <-stack.publishStarted:
		t.Fatal("UDP publish observed a policy whose persistence was still pending")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseWrite)
	if err := <-policyDone; !errors.Is(err, persistErr) {
		t.Fatalf("policy persistence error = %v, want %v", err, persistErr)
	} else if strings.Contains(err.Error(), "restore previous live network policy") {
		t.Fatalf("policy rollback was blocked by a concurrent UDP publish: %v", err)
	}
	if err := <-publishDone; err == nil || !strings.Contains(err.Error(), "gateway reply port") {
		t.Fatalf("UDP publish after policy rollback error = %v", err)
	}
	if err := netpol.ValidateUDPPortPublishing(live); err == nil {
		t.Fatal("failed policy transaction left the permissive policy active")
	}
	if forwards, err := stack.Forwards(); err != nil || len(forwards) != 0 {
		t.Fatalf("failed transaction left active forwards %v (error %v)", forwards, err)
	}
}

func TestNetworkTransactionSerializesUDPUnpublishRollbackWithPolicyTightening(t *testing.T) {
	const spec = "127.0.0.1:48102:18082/udp"
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, config.RunConfig{
		Net: true, AllowLN: true,
	})
	policyPath := filepath.Join(dir, "deny-local.json")
	if err := os.WriteFile(policyPath, []byte(`{"default":"allow"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	persistErr := errors.New("injected unpublish persistence failure")
	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	var writeOnce sync.Once
	store.SetWriter(func(string, []byte, os.FileMode) error {
		writeOnce.Do(func() { close(writeStarted) })
		<-releaseWrite
		return persistErr
	})

	live := mustTestPolicy(t, `{"default":"allow","allowLocal":true}`)
	stack := &localNetworkStackStub{
		forwards: []vnet.Forward{{
			Protocol: "udp", Local: "127.0.0.1:48102", Remote: vnet.GuestIP + ":18082",
		}},
		publishStarted:   make(chan struct{}),
		unpublishStarted: make(chan struct{}),
	}
	local := &localBackend{stack: stack, live: live}
	backend := &blockedPolicyBackend{
		NetworkBackend: local,
		started:        make(chan struct{}),
		release:        make(chan struct{}),
	}
	transactions := NewNetworkTransactionCoordinator()
	policies := NewNetworkPolicyManagerWithCoordinator(store, backend, live, transactions)
	ports := NewPortManagerWithCoordinator(store, backend, transactions)

	policyDone := make(chan error, 1)
	go func() {
		_, err := policies.Set(policyPath, false)
		policyDone <- err
	}()
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("policy transaction did not reach the backend")
	}

	unpublishAttempted := make(chan struct{})
	unpublishDone := make(chan error, 1)
	go func() {
		close(unpublishAttempted)
		_, err := ports.Unpublish(spec, true)
		unpublishDone <- err
	}()
	<-unpublishAttempted
	select {
	case <-stack.unpublishStarted:
		t.Fatal("UDP unpublish overtook an in-flight policy transaction")
	case <-time.After(50 * time.Millisecond):
	}

	close(backend.release)
	if err := <-policyDone; err == nil || !strings.Contains(err.Error(), "gateway reply port") {
		t.Fatalf("policy tightening with active UDP forward error = %v", err)
	}
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("unpublish transaction did not reach persistence")
	}
	close(releaseWrite)
	if err := <-unpublishDone; !errors.Is(err, persistErr) {
		t.Fatalf("unpublish persistence error = %v, want %v", err, persistErr)
	} else if strings.Contains(err.Error(), "restore unpublished listener") {
		t.Fatalf("unpublish rollback was blocked by a concurrent policy update: %v", err)
	}
	select {
	case <-stack.publishStarted:
	default:
		t.Fatal("failed unpublish did not restore its listener")
	}
	if err := netpol.ValidateUDPPortPublishing(live); err != nil {
		t.Fatalf("rejected policy tightening changed the permissive live policy: %v", err)
	}
	if forwards, err := stack.Forwards(); err != nil || len(forwards) != 1 || forwards[0].Protocol != "udp" {
		t.Fatalf("unpublish rollback forwards = %v (error %v)", forwards, err)
	}
	if saved := store.Snapshot().Ports; len(saved) != 0 {
		t.Fatalf("unpublish rollback saved ports = %v", saved)
	}
}

func TestNetworkPolicyRejectsTighteningWithSavedUnboundUDPForward(t *testing.T) {
	const spec = "127.0.0.1:48103:18083/udp"
	dir := t.TempDir()
	store := newTestConfigStore(t, dir, config.RunConfig{
		Net: true, AllowLN: true, Ports: []string{spec},
	})
	policyPath := filepath.Join(dir, "deny-local.json")
	if err := os.WriteFile(policyPath, []byte(`{"default":"allow"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	live := mustTestPolicy(t, `{"default":"allow","allowLocal":true}`)
	stack := &localNetworkStackStub{forwards: []vnet.Forward{{
		Protocol: "udp", Local: "127.0.0.1:48103", Remote: vnet.GuestIP + ":18083",
	}}}
	backend := &localBackend{stack: stack, live: live}
	transactions := NewNetworkTransactionCoordinator()
	ports := NewPortManagerWithCoordinator(store, backend, transactions)
	policies := NewNetworkPolicyManagerWithCoordinator(store, backend, live, transactions)

	// Ephemeral unpublish deliberately leaves the desired boot mapping saved.
	if _, err := ports.Unpublish(spec, false); err != nil {
		t.Fatal(err)
	}
	if forwards, err := stack.Forwards(); err != nil || len(forwards) != 0 {
		t.Fatalf("ephemeral unpublish left active forwards %v (error %v)", forwards, err)
	}
	if _, err := policies.Set(policyPath, false); err == nil || !strings.Contains(err.Error(), "saved UDP port forward") {
		t.Fatalf("policy tightening with saved UDP mapping error = %v", err)
	}
	if err := netpol.ValidateUDPPortPublishing(live); err != nil {
		t.Fatalf("rejected tightening changed the live policy: %v", err)
	}
	if saved := store.Snapshot().Ports; len(saved) != 1 || saved[0] != spec {
		t.Fatalf("rejected tightening changed saved ports: %v", saved)
	}
}
