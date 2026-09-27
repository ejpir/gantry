package policyfeed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policy/policytest"
)

func TestReceiverAppliesNewGenerationAndPersistsCursor(t *testing.T) {
	snapshot := policytest.Signed(t, policy.Profile{})
	var requests atomic.Int32
	var desired = feedResponse{Version: 1, Organization: "test-org", Generation: 7, Bundle: snapshot.Bundle}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestNumber := requests.Add(1)
		if r.Header.Get("Accept") != "application/json" || r.Header.Get("Prefer") != "wait=30" {
			t.Errorf("request headers = %#v", r.Header)
		}
		if requestNumber > 1 {
			if r.Header.Get("If-None-Match") != `"generation-7"` {
				t.Errorf("If-None-Match = %q", r.Header.Get("If-None-Match"))
			}
			if r.Header.Get("X-Gantry-Policy-Generation") != "7" || len(r.Header.Get("X-Gantry-Policy-Digest")) != 64 {
				t.Errorf("applied policy headers = %q/%q", r.Header.Get("X-Gantry-Policy-Generation"), r.Header.Get("X-Gantry-Policy-Digest"))
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"generation-7"`)
		_ = json.NewEncoder(w).Encode(desired)
	}))
	defer server.Close()

	config := &Config{Organization: "test-org", Profile: "dev", URL: server.URL, publicKey: snapshot.PublicKey}
	var applied atomic.Int32
	stateDir := t.TempDir()
	receiver, err := newReceiver(config, stateDir, nil, func(_ context.Context, update Update) error {
		applied.Add(1)
		if update.Generation != 7 || update.Info.Revision != "r1" || update.Snapshot.PublicKey != snapshot.PublicKey {
			t.Fatalf("update = %#v", update)
		}
		return nil
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if applied.Load() != 1 {
		t.Fatalf("apply calls = %d, want 1", applied.Load())
	}
	if requests.Load() != 2 {
		t.Fatalf("requests = %d, want 2", requests.Load())
	}
	raw, err := os.ReadFile(receiver.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "BEGIN") || !strings.Contains(string(raw), `"bundle"`) {
		t.Fatal("cursor must cache the signed bundle but not trust or private-key PEM")
	}

	// A fresh manager replays its authenticated cache before polling so new
	// sandboxes cannot start unmanaged while the service answers 304.
	var replayed atomic.Int32
	restored, err := newReceiver(config, stateDir, nil, func(context.Context, Update) error {
		replayed.Add(1)
		return nil
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if replayed.Load() != 1 {
		t.Fatalf("restored apply calls = %d, want 1", replayed.Load())
	}

	var tampered receiverState
	if err := json.Unmarshal(raw, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Bundle[0] ^= 0xff
	tamperedRaw, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiver.statePath, tamperedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newReceiver(config, stateDir, nil, func(context.Context, Update) error { return nil }, server.Client()); err == nil || !strings.Contains(err.Error(), "invalid policy channel state") {
		t.Fatalf("tampered cached bundle error = %v", err)
	}
}

func TestReceiverRejectsRollbackAndGenerationContentChange(t *testing.T) {
	first := policytest.Signed(t, policy.Profile{})
	second := policytest.Document(t, policy.Document{
		Version: 1, Organization: "test-org", Revision: "r2",
		ExpiresAt: firstPolicyExpiry(t, first), Profiles: map[string]policy.Profile{"dev": {}},
	})
	desired := feedResponse{Version: 1, Organization: "test-org", Generation: 4, Bundle: first.Bundle}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(desired)
	}))
	defer server.Close()
	config := &Config{Organization: "test-org", Profile: "dev", URL: server.URL, publicKey: first.PublicKey}
	var applied atomic.Int32
	receiver, err := newReceiver(config, t.TempDir(), nil, func(context.Context, Update) error {
		applied.Add(1)
		return nil
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	desired.Generation = 3
	if err := receiver.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "rollback refused") {
		t.Fatalf("rollback error = %v", err)
	}
	desired.Generation = 4
	desired.Bundle = second.Bundle
	if err := receiver.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "changed content") {
		t.Fatalf("content-change error = %v", err)
	}
	if applied.Load() != 1 {
		t.Fatalf("apply calls = %d, want 1", applied.Load())
	}
}

func TestReceiverAcknowledgesOnlyCompleteOrganizationRollout(t *testing.T) {
	snapshot := policytest.Signed(t, policy.Profile{})
	desired := feedResponse{Version: 1, Organization: "test-org", Generation: 9, Bundle: snapshot.Bundle}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"generation-9"`)
		_ = json.NewEncoder(w).Encode(desired)
	}))
	defer server.Close()

	config := &Config{Organization: "test-org", Profile: "dev", URL: server.URL, publicKey: snapshot.PublicKey}
	var attempts atomic.Int32
	stateDir := t.TempDir()
	receiver, err := newReceiver(config, stateDir, nil, func(context.Context, Update) error {
		if attempts.Add(1) == 1 {
			return context.DeadlineExceeded
		}
		return nil
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "apply generation 9") {
		t.Fatalf("incomplete rollout error = %v", err)
	}
	if receiver.state.Generation != 0 || receiver.state.PendingGeneration != 9 {
		t.Fatalf("failed rollout applied/pending generation = %d/%d, want 0/9", receiver.state.Generation, receiver.state.PendingGeneration)
	}
	raw, err := os.ReadFile(receiver.statePath)
	if err != nil {
		t.Fatal(err)
	}
	var staged receiverState
	if err := json.Unmarshal(raw, &staged); err != nil {
		t.Fatal(err)
	}
	if staged.Generation != 0 || staged.PendingGeneration != 9 {
		t.Fatalf("durable applied/pending generation = %d/%d, want 0/9", staged.Generation, staged.PendingGeneration)
	}
	restarted, err := newReceiver(config, stateDir, nil, func(context.Context, Update) error {
		attempts.Add(1)
		return nil
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restarted.state.Generation != 9 || restarted.state.PendingGeneration != 0 || attempts.Load() != 2 {
		t.Fatalf("restored applied/pending/attempts = %d/%d/%d", restarted.state.Generation, restarted.state.PendingGeneration, attempts.Load())
	}
}

func firstPolicyExpiry(t *testing.T, snapshot *policy.Config) time.Time {
	t.Helper()
	engine, err := policy.New(snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	return engine.Info().ExpiresAt
}

func TestReceiverReportsStalledRolloutAndAcceptsFixForward(t *testing.T) {
	stuck := policytest.Signed(t, policy.Profile{})
	fixed := policytest.Document(t, policy.Document{
		Version: 1, Organization: "test-org", Revision: "r2",
		ExpiresAt: firstPolicyExpiry(t, stuck), Profiles: map[string]policy.Profile{"dev": {}},
	})
	desired := feedResponse{Version: 1, Organization: "test-org", Generation: 9, Bundle: stuck.Bundle}
	etag := `"generation-9"`
	var reports []http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reports = append(reports, r.Header.Clone())
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", etag)
		_ = json.NewEncoder(w).Encode(desired)
	}))
	defer server.Close()

	config := &Config{Organization: "test-org", Profile: "dev", URL: server.URL, publicKey: stuck.PublicKey}
	receiver, err := newReceiver(config, t.TempDir(), nil, func(_ context.Context, update Update) error {
		if update.Generation == 9 {
			return &RolloutError{Failed: 1, Total: 3, Err: errors.New("sandbox bad: reconcile failed")}
		}
		return nil
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	var incomplete incompleteError
	if err := receiver.Sync(context.Background()); !errors.As(err, &incomplete) {
		t.Fatalf("first stalled sync = %v, want an incomplete rollout", err)
	}
	// The retry fails again, yet the host still polls and says so.
	if err := receiver.Sync(context.Background()); !errors.As(err, &incomplete) {
		t.Fatalf("second stalled sync = %v, want an incomplete rollout", err)
	}
	report := reports[1]
	for header, want := range map[string]string{
		"X-Gantry-Policy-Pending-Generation": "9",
		"X-Gantry-Policy-Pending-Attempts":   "2",
		"X-Gantry-Policy-Pending-Failed":     "1",
		"X-Gantry-Policy-Profile":            "dev",
		"If-None-Match":                      `"generation-9"`,
		"X-Gantry-Policy-Generation":         "",
	} {
		if got := report.Get(header); got != want {
			t.Errorf("stalled report %s = %q, want %q", header, got, want)
		}
	}
	if !strings.HasPrefix(report.Get("User-Agent"), "gantry/") {
		t.Errorf("User-Agent = %q", report.Get("User-Agent"))
	}

	// A newer generation replaces the stuck one instead of waiting behind it.
	desired = feedResponse{Version: 1, Organization: "test-org", Generation: 10, Bundle: fixed.Bundle}
	etag = `"generation-10"`
	if err := receiver.Sync(context.Background()); err != nil {
		t.Fatalf("fix-forward sync = %v", err)
	}
	if receiver.state.Generation != 10 || receiver.state.PendingGeneration != 0 {
		t.Fatalf("applied/pending after fix = %d/%d, want 10/0", receiver.state.Generation, receiver.state.PendingGeneration)
	}
	if err := receiver.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	report = reports[len(reports)-1]
	if report.Get("X-Gantry-Policy-Generation") != "10" || report.Get("X-Gantry-Policy-Pending-Generation") != "" || report.Get("X-Gantry-Policy-Pending-Failed") != "" {
		t.Fatalf("report after fix = %#v", report)
	}
}

func TestReceiverReportsRejectedGenerations(t *testing.T) {
	good := policytest.Signed(t, policy.Profile{})
	other := policytest.Document(t, policy.Document{
		Version: 1, Organization: "other-org", Revision: "r1",
		ExpiresAt: firstPolicyExpiry(t, good), Profiles: map[string]policy.Profile{"dev": {}},
	})
	corrupt := bytes.Clone(good.Bundle)
	corrupt[len(corrupt)/2] ^= 0xff
	desired := feedResponse{Version: 1, Organization: "test-org", Generation: 5, Bundle: good.Bundle}
	var last http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(desired)
	}))
	defer server.Close()
	config := &Config{Organization: "test-org", Profile: "dev", URL: server.URL, publicKey: good.PublicKey}
	receiver, err := newReceiver(config, t.TempDir(), nil, func(context.Context, Update) error { return nil }, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		generation uint64
		bundle     []byte
		reason     string
	}{
		{6, corrupt, RejectVerification},
		{7, other.Bundle, RejectOrganization},
		{4, good.Bundle, RejectRollback},
	} {
		desired = feedResponse{Version: 1, Organization: "test-org", Generation: step.generation, Bundle: step.bundle}
		if err := receiver.Sync(context.Background()); err == nil {
			t.Fatalf("generation %d was accepted", step.generation)
		}
		desired = feedResponse{Version: 1, Organization: "test-org", Generation: 5, Bundle: good.Bundle}
		if err := receiver.Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
		if last.Get("X-Gantry-Policy-Rejected-Reason") != step.reason || last.Get("X-Gantry-Policy-Rejected-Generation") != fmt.Sprint(step.generation) {
			t.Fatalf("rejection report = %q/%q, want %s/%d", last.Get("X-Gantry-Policy-Rejected-Reason"), last.Get("X-Gantry-Policy-Rejected-Generation"), step.reason, step.generation)
		}
		if last.Get("X-Gantry-Policy-Generation") != "5" {
			t.Fatalf("applied cursor moved to %q", last.Get("X-Gantry-Policy-Generation"))
		}
	}
}

func TestReceiverReportsAppliedGenerationWithoutWaitingAPollInterval(t *testing.T) {
	snapshot := policytest.Signed(t, policy.Profile{})
	reported := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reported <- r.Header.Get("X-Gantry-Policy-Generation")
		if r.Header.Get("If-None-Match") == `"g3"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"g3"`)
		_ = json.NewEncoder(w).Encode(feedResponse{Version: 1, Organization: "test-org", Generation: 3, Bundle: snapshot.Bundle})
	}))
	defer server.Close()
	config := &Config{Organization: "test-org", Profile: "dev", URL: server.URL, publicKey: snapshot.PublicKey, poll: time.Hour}
	receiver, err := newReceiver(config, t.TempDir(), nil, func(context.Context, Update) error { return nil }, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go receiver.Run(ctx)
	for i, want := range []string{"", "3"} {
		select {
		case got := <-reported:
			if got != want {
				t.Fatalf("poll %d reported generation %q, want %q", i, got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("poll %d did not happen promptly", i)
		}
	}
}
