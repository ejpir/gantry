package policyservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	api "github.com/ejpir/gantry/api/policyservice"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/policyfeed"
)

var testKey = sync.OnceValues(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) })

type harness struct {
	t       *testing.T
	service *Service
	url     string
	admin   *http.Client
	token   string
	key     *rsa.PrivateKey
	expires time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	key, err := testKey()
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "service")
	if err := Init(InitOptions{Dir: dir, Organization: "acme", URL: "https://127.0.0.1:8443", PublicKey: pemBlock("PUBLIC KEY", public)}); err != nil {
		t.Fatal(err)
	}
	token, err := AddAdmin(dir, "ops-admin")
	if err != nil {
		t.Fatal(err)
	}
	service, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.wait = 2 * time.Second
	listener, err := tls.Listen("tcp", "127.0.0.1:0", service.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: service.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(service.caPEM)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	return &harness{t: t, service: service, url: "https://" + listener.Addr().String(), admin: client, token: token, key: key,
		expires: time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)}
}

func (h *harness) call(method, route string, body any, want int, out any) []byte {
	h.t.Helper()
	status, raw := h.request(method, route, body, h.token)
	if status != want {
		h.t.Fatalf("%s %s = %d %s, want %d", method, route, status, raw, want)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			h.t.Fatalf("%s %s: %v in %s", method, route, err, raw)
		}
	}
	return raw
}

func (h *harness) request(method, route string, body any, token string) (int, []byte) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequest(method, h.url+route, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := h.admin.Do(request)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	raw, _ := io.ReadAll(response.Body)
	return response.StatusCode, raw
}

func (h *harness) sign(revision string, profiles map[string]policy.Profile) []byte {
	h.t.Helper()
	signed, err := policy.SignDocument(policy.Document{Version: 1, Organization: "acme", Revision: revision,
		ExpiresAt: h.expires, Profiles: profiles}, h.key)
	if err != nil {
		h.t.Fatal(err)
	}
	return signed.Bundle
}

func (h *harness) publish(bundle []byte, firstRing string) api.Generation {
	h.t.Helper()
	var generation api.Generation
	h.call(http.MethodPost, "/v1/admin/generations", api.PublishRequest{Bundle: bundle, FirstRing: firstRing}, http.StatusCreated, &generation)
	return generation
}

type testHost struct {
	receiver *policyfeed.Receiver
	mu       sync.Mutex
	applied  []uint64
	fail     map[uint64]bool
}

// enroll runs the real host flow: key and request on the host, enrollment by
// an administrator, and a receiver loaded from the returned feed.json.
func (h *harness) enroll(name, profile, ring string) *testHost {
	h.t.Helper()
	keyPEM, csrPEM, err := NewHostRequest(name)
	if err != nil {
		h.t.Fatal(err)
	}
	var enrollment api.Enrollment
	h.call(http.MethodPost, "/v1/admin/hosts", api.EnrollRequest{Name: name, Profile: profile, Ring: ring, CSR: string(csrPEM)}, http.StatusCreated, &enrollment)
	dir := h.t.TempDir()
	for file, content := range enrollment.Files {
		if file == api.FeedConfigFile {
			var config map[string]any
			if err := json.Unmarshal([]byte(content), &config); err != nil {
				h.t.Fatal(err)
			}
			if config["url"] != "https://127.0.0.1:8443/v1/feed" {
				h.t.Fatalf("feed.json url = %v", config["url"])
			}
			config["url"] = h.url + "/v1/feed"
			raw, _ := json.Marshal(config)
			content = string(raw)
		}
		if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o600); err != nil {
			h.t.Fatal(err)
		}
	}
	// os.WriteFile mode bits do not protect Windows files from inherited ACLs.
	if err := writePrivate(filepath.Join(dir, api.HostKeyFile), keyPEM); err != nil {
		h.t.Fatal(err)
	}
	config, err := policyfeed.LoadConfig(filepath.Join(dir, api.FeedConfigFile))
	if err != nil {
		h.t.Fatal(err)
	}
	host := &testHost{fail: map[uint64]bool{}}
	host.receiver, err = policyfeed.NewReceiver(config, filepath.Join(dir, "state"), nil, func(_ context.Context, update policyfeed.Update) error {
		host.mu.Lock()
		defer host.mu.Unlock()
		if host.fail[update.Generation] {
			return &policyfeed.RolloutError{Failed: 1, Total: 2, Err: errors.New("sandbox bad: cannot reconcile")}
		}
		host.applied = append(host.applied, update.Generation)
		return nil
	})
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(host.receiver.Close)
	return host
}

func (host *testHost) sync(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return host.receiver.Sync(ctx)
}

func (host *testHost) last() uint64 {
	host.mu.Lock()
	defer host.mu.Unlock()
	if len(host.applied) == 0 {
		return 0
	}
	return host.applied[len(host.applied)-1]
}

func (h *harness) hosts() map[string]api.Host {
	h.t.Helper()
	var hosts []api.Host
	h.call(http.MethodGet, "/v1/admin/hosts", nil, http.StatusOK, &hosts)
	byName := map[string]api.Host{}
	for _, host := range hosts {
		byName[host.Name] = host
	}
	return byName
}

// A mount path must be absolute and clean on the platform signing the bundle.
var testSourcePath = filepath.Join(os.TempDir(), "gantry-policyservice", "src")

func developer(dns ...string) map[string]policy.Profile {
	return map[string]policy.Profile{"developer": {
		Rules:   []policy.Rule{{ID: "src-read", Effect: "allow", Action: policy.MountRead, Path: testSourcePath}},
		Network: policy.Network{Rules: []netpol.GuardRule{{ID: "https", Effect: "allow", CIDR: "0.0.0.0/0", Protocol: "tcp", Ports: []uint16{443}}}, DNS: dns},
	}}
}

func TestServiceRollsOutRingByRingAndReportsHosts(t *testing.T) {
	h := newHarness(t)
	var health api.Health
	h.call(http.MethodGet, "/v1/health", nil, http.StatusOK, &health)
	if !health.OK || health.Version != "v1" || len(health.Capabilities) != 1 || health.Capabilities[0] != api.CapabilityAdmin {
		t.Fatalf("health = %+v", health)
	}
	canary := h.enroll("build-eu-1", "developer", "canary")
	everyone := h.enroll("dev-mac-003", "developer", "everyone")

	// Nothing published: the feed has nothing to serve and holds the poll.
	if err := canary.sync(t); err != nil {
		t.Fatalf("idle poll = %v", err)
	}
	first := h.publish(h.sign("r1", developer("github.com")), "")
	if first.Number != 1 || first.PublishedBy != "ops-admin" || len(first.Changes) != 1 || first.Changes[0].Kind != api.ChangeProfile {
		t.Fatalf("first generation = %+v", first)
	}
	if err := canary.sync(t); err != nil || canary.last() != 1 {
		t.Fatalf("canary sync = %v, applied %d", err, canary.last())
	}
	if err := everyone.sync(t); err != nil || everyone.last() != 0 {
		t.Fatalf("held ring received a generation: %v, applied %d", err, everyone.last())
	}
	if err := canary.sync(t); err != nil {
		t.Fatal(err)
	}
	hosts := h.hosts()
	if got := hosts["build-eu-1"]; got.Status != api.HostCurrent || got.Report == nil || !got.Report.DigestMatches || got.AcknowledgedAt == nil || !strings.HasPrefix(got.Report.Agent, "gantry/") || got.Report.Profile != "developer" {
		t.Fatalf("canary host = %+v report %+v", got, got.Report)
	}
	if got := hosts["dev-mac-003"]; got.Status != api.HostIdle || got.Target != 0 {
		t.Fatalf("held host = %+v", got)
	}
	var overview api.Overview
	h.call(http.MethodGet, "/v1/admin/overview", nil, http.StatusOK, &overview)
	if overview.Rollout == nil || overview.Rollout.Generation != 1 || overview.Rollout.Complete || overview.Rollout.Rings[0].Acknowledged != 1 || overview.Rollout.Rings[2].PromotedAt != nil {
		t.Fatalf("rollout = %+v", overview.Rollout)
	}

	h.call(http.MethodPost, "/v1/admin/rollout/promote", api.PromoteRequest{Ring: "everyone"}, http.StatusOK, &overview)
	if err := everyone.sync(t); err != nil || everyone.last() != 1 {
		t.Fatalf("promoted sync = %v, applied %d", err, everyone.last())
	}

	// A generation one host cannot apply shows up as stalled, with counts.
	everyone.fail[2] = true
	second := h.publish(h.sign("r2", developer("github.com", "registry.npmjs.org")), "everyone")
	if len(second.Changes) != 1 || second.Changes[0].Kind != api.ChangeDNS || second.Changes[0].Effect != api.EffectLoosens {
		t.Fatalf("second changes = %+v", second.Changes)
	}
	if err := everyone.sync(t); err == nil {
		t.Fatal("failing rollout reported success")
	}
	if err := everyone.sync(t); err == nil {
		t.Fatal("failing rollout reported success on retry")
	}
	stalled := h.hosts()["dev-mac-003"]
	if stalled.Status != api.HostStalled || stalled.Report.Pending != 2 || stalled.Report.Failed == nil || *stalled.Report.Failed != 1 || stalled.Report.Attempts < 1 {
		t.Fatalf("stalled host = %+v report %+v", stalled, stalled.Report)
	}

	// Fixing forward reaches the stuck host.
	third := h.publish(h.sign("r3", developer("github.com")), "everyone")
	if err := everyone.sync(t); err != nil || everyone.last() != third.Number {
		t.Fatalf("fix-forward sync = %v, applied %d", err, everyone.last())
	}

	// Rolling back republishes an old bundle under a new number.
	var rollback api.Generation
	h.call(http.MethodPost, "/v1/admin/generations/1/republish", api.RepublishRequest{FirstRing: "everyone"}, http.StatusCreated, &rollback)
	if rollback.Number != 4 || rollback.RepublishOf != 1 || rollback.BundleSHA256 != first.BundleSHA256 {
		t.Fatalf("rollback = %+v", rollback)
	}
	for _, host := range []*testHost{canary, everyone} {
		if err := host.sync(t); err != nil || host.last() != 4 {
			t.Fatalf("rollback sync = %v, applied %d", err, host.last())
		}
	}
	var generations []api.Generation
	h.call(http.MethodGet, "/v1/admin/generations", nil, http.StatusOK, &generations)
	if len(generations) != 4 || generations[0].Number != 4 {
		t.Fatalf("generations = %+v", generations)
	}
	status, raw := h.request(http.MethodGet, "/v1/admin/generations/1/bundle", nil, h.token)
	if status != http.StatusOK || generations[3].Size != len(raw) {
		t.Fatalf("bundle download = %d, %d bytes", status, len(raw))
	}

	// Revoked hosts are refused by the feed.
	h.call(http.MethodPost, "/v1/admin/hosts/build-eu-1/revoke", nil, http.StatusOK, nil)
	if err := canary.sync(t); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("revoked host sync = %v", err)
	}
	if got := h.hosts()["build-eu-1"]; got.Status != api.HostRevoked || got.RevokedBy != "ops-admin" {
		t.Fatalf("revoked host = %+v", got)
	}
}

func TestServiceLongPollWakesOnPublish(t *testing.T) {
	h := newHarness(t)
	h.service.wait = 10 * time.Second
	host := h.enroll("dev-lin-007", "developer", "canary")
	h.publish(h.sign("r1", developer()), "")
	if err := host.sync(t); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	started := time.Now()
	go func() { done <- host.sync(t) }()
	time.Sleep(200 * time.Millisecond)
	h.publish(h.sign("r2", developer("github.com")), "")
	select {
	case err := <-done:
		if err != nil || host.last() != 2 {
			t.Fatalf("woken sync = %v, applied %d", err, host.last())
		}
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Fatalf("publish took %s to reach a waiting host", elapsed)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("a waiting host was not woken by publish")
	}
}

func TestServiceRefusesUntrustedAndInconsistentInput(t *testing.T) {
	h := newHarness(t)
	for _, token := range []string{"", "wrong-token-0123456789"} {
		if status, _ := h.request(http.MethodGet, "/v1/admin/overview", nil, token); status != http.StatusForbidden {
			t.Fatalf("token %q status = %d", token, status)
		}
	}
	if status, _ := h.request(http.MethodGet, "/v1/feed", nil, h.token); status != http.StatusForbidden {
		t.Fatalf("feed without a client certificate = %d", status)
	}

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := policy.SignDocument(policy.Document{Version: 1, Organization: "acme", Revision: "r1",
		ExpiresAt: time.Now().Add(time.Hour), Profiles: developer()}, other)
	if err != nil {
		t.Fatal(err)
	}
	if status, raw := h.request(http.MethodPost, "/v1/admin/generations", api.PublishRequest{Bundle: foreign.Bundle}, h.token); status != http.StatusUnprocessableEntity || !strings.Contains(string(raw), "does not verify") {
		t.Fatalf("foreign-key bundle = %d %s", status, raw)
	}

	h.enroll("ci-runner-1", "ci", "early")
	if status, raw := h.request(http.MethodPost, "/v1/admin/generations", api.PublishRequest{Bundle: h.sign("r1", developer())}, h.token); status != http.StatusUnprocessableEntity || !strings.Contains(string(raw), `profile \"ci\"`) {
		t.Fatalf("bundle missing an enrolled profile = %d %s", status, raw)
	}
	profiles := developer()
	profiles["ci"] = policy.Profile{}
	bundle := h.sign("r1", profiles)
	h.publish(bundle, "")
	if status, _ := h.request(http.MethodPost, "/v1/admin/generations", api.PublishRequest{Bundle: bundle}, h.token); status != http.StatusConflict {
		t.Fatalf("republishing the latest bundle = %d", status)
	}
	if status, raw := h.request(http.MethodPost, "/v1/admin/hosts", api.EnrollRequest{Name: "x", Profile: "nope", Ring: "early", CSR: "-"}, h.token); status != http.StatusUnprocessableEntity || !strings.Contains(string(raw), `profile \"nope\"`) {
		t.Fatalf("unknown profile enrollment = %d %s", status, raw)
	}
	if status, _ := h.request(http.MethodPost, "/v1/admin/hosts", api.EnrollRequest{Name: "ci-runner-1", Profile: "ci", Ring: "early", CSR: "-"}, h.token); status != http.StatusConflict {
		t.Fatalf("duplicate enrollment = %d", status)
	}
	if status, _ := h.request(http.MethodPost, "/v1/admin/hosts", api.EnrollRequest{Name: "y", Profile: "ci", Ring: "early", CSR: "not a request"}, h.token); status != http.StatusUnprocessableEntity {
		t.Fatalf("invalid request enrollment = %d", status)
	}
}

func TestServiceDraftsValidateAndClearOnPublish(t *testing.T) {
	h := newHarness(t)
	var draft api.Draft
	h.call(http.MethodGet, "/v1/admin/draft", nil, http.StatusOK, &draft)
	if draft.Saved || draft.Base != 0 || !strings.Contains(string(draft.Data), `"developer"`) {
		t.Fatalf("initial draft = %+v %s", draft, draft.Data)
	}
	first := h.publish(h.sign("r1", developer("github.com")), "")
	h.call(http.MethodGet, "/v1/admin/draft", nil, http.StatusOK, &draft)
	if draft.Saved || draft.Base != first.Number || len(draft.Changes) != 0 {
		t.Fatalf("draft from latest = %+v", draft)
	}

	var root struct {
		Gantry policy.Document `json:"gantry"`
	}
	if err := json.Unmarshal(draft.Data, &root); err != nil {
		t.Fatal(err)
	}
	profile := root.Gantry.Profiles["developer"]
	profile.Network.Rules = append(profile.Network.Rules, netpol.GuardRule{ID: "staging-db", Effect: "allow", CIDR: "10.20.0.0/16", Protocol: "tcp", Ports: []uint16{5432}})
	profile.Rules = nil
	root.Gantry.Profiles["developer"] = profile
	root.Gantry.Revision = "r2"
	edited, _ := json.Marshal(root)
	h.call(http.MethodPut, "/v1/admin/draft", api.DraftRequest{Base: first.Number, Data: edited}, http.StatusOK, &draft)
	if !draft.Saved || draft.UpdatedBy != "ops-admin" || len(draft.Changes) != 2 {
		t.Fatalf("saved draft = %+v", draft)
	}
	effects := map[string]string{}
	for _, change := range draft.Changes {
		effects[change.ID] = change.Change + "/" + change.Effect
	}
	if effects["staging-db"] != "added/loosens" || effects["src-read"] != "removed/tightens" {
		t.Fatalf("draft changes = %+v", draft.Changes)
	}

	duplicate := bytes.Replace(edited, []byte(`"staging-db"`), []byte(`"https"`), 1)
	if status, raw := h.request(http.MethodPut, "/v1/admin/draft", api.DraftRequest{Base: first.Number, Data: duplicate}, h.token); status != http.StatusUnprocessableEntity {
		t.Fatalf("duplicate rule id draft = %d %s", status, raw)
	}

	// Publishing exactly the reviewed draft clears it.
	var document struct {
		Gantry policy.Document `json:"gantry"`
	}
	if err := json.Unmarshal(draft.Data, &document); err != nil {
		t.Fatal(err)
	}
	signed, err := policy.SignDocument(document.Gantry, h.key)
	if err != nil {
		t.Fatal(err)
	}
	h.publish(signed.Bundle, "")
	h.call(http.MethodGet, "/v1/admin/draft", nil, http.StatusOK, &draft)
	if draft.Saved || draft.Base != 2 {
		t.Fatalf("draft after publishing it = %+v", draft)
	}
}

func TestServiceStatePersistsAcrossRestart(t *testing.T) {
	h := newHarness(t)
	host := h.enroll("dev-mac-014", "developer", "canary")
	h.publish(h.sign("r1", developer()), "")
	if err := host.sync(t); err != nil {
		t.Fatal(err)
	}
	h.service.FlushReports()
	reopened, err := Open(h.service.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	reopened.mu.Lock()
	defer reopened.mu.Unlock()
	stored := reopened.hostByNameLocked("dev-mac-014")
	if stored == nil || stored.Served != 1 || reopened.latestLocked() != 1 || reopened.state.Rings[0].Generation != 1 {
		t.Fatalf("reopened state = %+v", reopened.state)
	}
	if _, err := reopened.documentLocked(1); err != nil {
		t.Fatal(err)
	}
}

func TestInitRefusesExistingDirectoryAndWeakKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := testKey()
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err := Init(InitOptions{Dir: dir, Organization: "acme", URL: "https://policy.example:8443", PublicKey: pemBlock("PUBLIC KEY", public)}); err == nil {
		t.Fatal("init overwrote a non-empty directory")
	}
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	weakPublic, _ := x509.MarshalPKIXPublicKey(&weak.PublicKey)
	if err := Init(InitOptions{Dir: filepath.Join(dir, "new"), Organization: "acme", URL: "https://policy.example:8443", PublicKey: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: weakPublic})}); err == nil {
		t.Fatal("init accepted a 1024-bit key")
	}
	for _, bad := range []string{"http://policy.example", "https://policy.example/v1", "https://user@policy.example"} {
		if err := Init(InitOptions{Dir: filepath.Join(dir, "url"), Organization: "acme", URL: bad, PublicKey: pemBlock("PUBLIC KEY", public)}); err == nil {
			t.Fatalf("init accepted URL %s", bad)
		}
	}
}

func TestPreferWait(t *testing.T) {
	for value, want := range map[string]time.Duration{
		"wait=30": 30 * time.Second, "wait=5": 5 * time.Second, "respond-async, wait=10": 10 * time.Second,
		"wait=999": maxWait, "wait=-1": 0, "": 0, "wait=x": 0,
	} {
		if got := preferWait(value); got != want {
			t.Errorf("preferWait(%q) = %s, want %s", value, got, want)
		}
	}
}

func TestDiffClassifiesChanges(t *testing.T) {
	before := policy.Document{ExpiresAt: time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC), Profiles: map[string]policy.Profile{
		"developer": {
			Rules: []policy.Rule{
				{ID: "linear-delete", Effect: "allow", Action: policy.MCPCall, Server: "linear", Tool: "delete_issue"},
				{ID: "block-paste", Effect: "deny", Action: policy.CredentialUse, Host: "pastebin.com"},
				{ID: "src", Effect: "allow", Action: policy.MountRead, Path: testSourcePath},
			},
			Network: policy.Network{DNS: []string{"github.com", "old.example"}},
		},
		"retired": {},
	}}
	after := policy.Document{ExpiresAt: time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC), Profiles: map[string]policy.Profile{
		"developer": {
			Rules: []policy.Rule{{ID: "src", Effect: "deny", Action: policy.MountRead, Path: testSourcePath}},
			Network: policy.Network{
				Rules: []netpol.GuardRule{{ID: "staging-db", Effect: "allow", CIDR: "10.20.0.0/16", Protocol: "tcp", Ports: []uint16{5432}}},
				DNS:   []string{"github.com", "registry.npmjs.org"},
			},
		},
		"ci": {},
	}}
	got := map[string]string{}
	for _, change := range diffDocuments(&before, after) {
		got[fmt.Sprintf("%s/%s/%s", change.Profile, change.Kind, change.ID)] = change.Change + " " + change.Effect
	}
	want := map[string]string{
		"/expiry/":                         "changed neutral",
		"ci/profile/ci":                    "added neutral",
		"retired/profile/retired":          "removed tightens",
		"developer/network/staging-db":     "added loosens",
		"developer/dns/registry.npmjs.org": "added loosens",
		"developer/dns/old.example":        "removed tightens",
		"developer/rule/linear-delete":     "removed tightens",
		"developer/rule/block-paste":       "removed loosens",
		"developer/rule/src":               "changed tightens",
	}
	if len(got) != len(want) {
		t.Fatalf("changes = %v", got)
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %q, want %q", key, got[key], value)
		}
	}
}
