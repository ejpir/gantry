package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	policyapi "github.com/ejpir/gantry/api/policyservice"
)

const (
	policyFeedOrganization = "manager-e2e"
	policyFeedHost         = "e2e-manager"
)

// policyFeedHarness runs the real `gantry policy-service` binary: the
// manager under test is enrolled like any host (its own key and certificate
// request) and every generation is signed with `gantry policy sign`, then
// published and rolled out through the administrator API.
type policyFeedHarness struct {
	configPath string
	repo       string
	env        []string
	gantry     string
	work       string
	dataPath   string
	keyPath    string
	url        string
	token      string
	client     *http.Client
	service    *exec.Cmd
	exited     chan struct{}
	logPath    string
	signed     int
}

func setupPolicyFeed(ctx context.Context, repo string, env []string, gantry, work string) (*policyFeedHarness, error) {
	harness := &policyFeedHarness{repo: repo, env: env, gantry: gantry, work: work, logPath: filepath.Join(work, "policy-service.log")}
	policyDir := filepath.Join(work, "policy-feed-policy")
	if err := runCommand(ctx, repo, env, gantry, "policy", "generate", "-out", policyDir,
		"-organization", policyFeedOrganization, "-profile", "developer", "-ttl", "1h"); err != nil {
		return nil, fmt.Errorf("generate feed policy: %w", err)
	}
	harness.dataPath = filepath.Join(policyDir, "source", "data.json")

	// A stable signing key, as an organization would keep, outside every
	// directory the service or the host reads.
	keyDir := filepath.Join(work, "policy-key")
	if err := runCommand(ctx, repo, env, gantry, "policy", "keygen", "-out", keyDir); err != nil {
		return nil, fmt.Errorf("generate organization signing key: %w", err)
	}
	harness.keyPath = filepath.Join(keyDir, "signing-key.pem")
	publicPath := filepath.Join(keyDir, "public.pem")

	port, err := freeLoopbackPort()
	if err != nil {
		return nil, err
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	harness.url = "https://" + address
	serviceDir := filepath.Join(work, "policy-service")
	if err := runCommand(ctx, repo, env, gantry, "policy-service", "init", "-dir", serviceDir,
		"-organization", policyFeedOrganization, "-url", harness.url, "-public-key", publicPath); err != nil {
		return nil, fmt.Errorf("initialize policy service: %w", err)
	}
	if harness.token, err = runCommandOutput(ctx, repo, env, gantry, "policy-service", "admin", "add", "-dir", serviceDir, "-name", "e2e-admin"); err != nil {
		return nil, fmt.Errorf("create policy-service administrator: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(serviceDir, policyapi.CAFile))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("policy-service CA contains no certificates")
	}
	harness.client = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}

	logFile, err := os.OpenFile(harness.logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	harness.service = exec.Command(gantry, "policy-service", "serve", "-dir", serviceDir, "-listen", address)
	harness.service.Dir = repo
	harness.service.Env = env
	harness.service.Stdout = logFile
	harness.service.Stderr = logFile
	if err := harness.service.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("start policy service: %w", err)
	}
	harness.exited = make(chan struct{})
	go func() {
		_ = harness.service.Wait()
		_ = logFile.Close()
		close(harness.exited)
	}()
	if err := harness.waitHealthy(ctx); err != nil {
		harness.Close()
		return nil, err
	}

	// Enroll the manager under test exactly as a real host would.
	feedDir := filepath.Join(work, "policy-feed")
	if err := runCommand(ctx, repo, env, gantry, "policy", "feed-request", "-out", feedDir, "-host", policyFeedHost); err != nil {
		harness.Close()
		return nil, fmt.Errorf("create host request: %w", err)
	}
	csr, err := os.ReadFile(filepath.Join(feedDir, policyapi.HostRequestFile))
	if err != nil {
		harness.Close()
		return nil, err
	}
	var enrollment policyapi.Enrollment
	if err := harness.admin(ctx, http.MethodPost, "/v1/admin/hosts", policyapi.EnrollRequest{
		Name: policyFeedHost, Profile: "developer", Ring: "canary", CSR: string(csr),
	}, http.StatusCreated, &enrollment); err != nil {
		harness.Close()
		return nil, fmt.Errorf("enroll host: %w", err)
	}
	for _, name := range []string{policyapi.FeedConfigFile, policyapi.HostCertFile, policyapi.CAFile, policyapi.PublicKeyFile} {
		content, ok := enrollment.Files[name]
		if !ok {
			harness.Close()
			return nil, fmt.Errorf("enrollment is missing %s", name)
		}
		if err := os.WriteFile(filepath.Join(feedDir, name), []byte(content), 0o600); err != nil {
			harness.Close()
			return nil, err
		}
	}
	harness.configPath = filepath.Join(feedDir, policyapi.FeedConfigFile)
	return harness, nil
}

func (harness *policyFeedHarness) waitHealthy(ctx context.Context) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		var health policyapi.Health
		err := harness.admin(ctx, http.MethodGet, "/v1/health", nil, http.StatusOK, &health)
		if err == nil {
			if !health.OK || len(health.Capabilities) == 0 || health.Capabilities[0] != policyapi.CapabilityAdmin {
				return fmt.Errorf("unexpected policy-service health: %+v", health)
			}
			return nil
		}
		select {
		case <-harness.exited:
			printLogTail(harness.logPath, 40)
			return fmt.Errorf("policy service exited during startup")
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("policy service did not become healthy: %w", err)
		}
	}
}

func (harness *policyFeedHarness) admin(ctx context.Context, method, route string, body any, want int, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, harness.url+route, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+harness.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := harness.client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != want {
		return statusError(response.StatusCode, raw, want)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Publish signs the generated policy under revision with the stable key and
// publishes it; the host's ring (canary) receives it at once.
func (harness *policyFeedHarness) Publish(ctx context.Context, revision string) (uint64, error) {
	raw, err := os.ReadFile(harness.dataPath)
	if err != nil {
		return 0, err
	}
	var data map[string]map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return 0, err
	}
	data["gantry"]["revision"] = revision
	harness.signed++
	source := filepath.Join(harness.work, fmt.Sprintf("policy-source-%d.json", harness.signed))
	raw, err = json.MarshalIndent(data, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(source, raw, 0o600); err != nil {
		return 0, err
	}
	out := filepath.Join(harness.work, fmt.Sprintf("policy-signed-%d", harness.signed))
	if err := runCommand(ctx, harness.repo, harness.env, harness.gantry, "policy", "sign", "-data", source, "-signing-key", harness.keyPath, "-out", out); err != nil {
		return 0, fmt.Errorf("sign policy: %w", err)
	}
	bundle, err := os.ReadFile(filepath.Join(out, "bundle.tar.gz"))
	if err != nil {
		return 0, err
	}
	var generation policyapi.Generation
	if err := harness.admin(ctx, http.MethodPost, "/v1/admin/generations", policyapi.PublishRequest{Bundle: bundle}, http.StatusCreated, &generation); err != nil {
		return 0, fmt.Errorf("publish policy: %w", err)
	}
	if generation.Revision != revision || generation.PublishedBy != "e2e-admin" {
		return 0, fmt.Errorf("unexpected published generation: %+v", generation)
	}
	return generation.Number, nil
}

// Republish rolls back by serving generation's signed bundle as a new one.
func (harness *policyFeedHarness) Republish(ctx context.Context, generation uint64) (uint64, error) {
	var republished policyapi.Generation
	if err := harness.admin(ctx, http.MethodPost, fmt.Sprintf("/v1/admin/generations/%d/republish", generation), policyapi.RepublishRequest{}, http.StatusCreated, &republished); err != nil {
		return 0, fmt.Errorf("republish generation %d: %w", generation, err)
	}
	if republished.RepublishOf != generation {
		return 0, fmt.Errorf("unexpected republished generation: %+v", republished)
	}
	return republished.Number, nil
}

// WaitApplied waits until the host reports generation as fully applied, with
// the digest the service expects for its profile and the pinned key.
func (harness *policyFeedHarness) WaitApplied(ctx context.Context, generation uint64) (policyapi.Host, error) {
	for {
		var hosts []policyapi.Host
		if err := harness.admin(ctx, http.MethodGet, "/v1/admin/hosts", nil, http.StatusOK, &hosts); err != nil {
			return policyapi.Host{}, err
		}
		for _, host := range hosts {
			if host.Name == policyFeedHost && host.Status == policyapi.HostCurrent && host.Report != nil &&
				host.Report.Applied == generation && host.Report.DigestMatches {
				return host, nil
			}
		}
		select {
		case <-ctx.Done():
			return policyapi.Host{}, fmt.Errorf("host never reported generation %d: %w (last: %+v)", generation, ctx.Err(), hosts)
		case <-harness.exited:
			return policyapi.Host{}, fmt.Errorf("policy service exited")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (harness *policyFeedHarness) Close() {
	if harness == nil || harness.service == nil || harness.service.Process == nil {
		return
	}
	_ = harness.service.Process.Signal(os.Interrupt)
	select {
	case <-harness.exited:
	case <-time.After(10 * time.Second):
		_ = harness.service.Process.Kill()
		<-harness.exited
	}
}

// testPolicyServiceEmptyHost rolls generations out to a manager without
// sandboxes: the aggregate fan-out is empty, but enrollment, signing,
// long-poll delivery, host reports, and rollback are all real.
func testPolicyServiceEmptyHost(ctx context.Context, harness *policyFeedHarness) error {
	first, err := harness.Publish(ctx, "e2e-r1")
	if err != nil {
		return err
	}
	for _, next := range []func() (uint64, error){
		func() (uint64, error) { return first, nil },
		func() (uint64, error) { return harness.Publish(ctx, "e2e-r2") },
		func() (uint64, error) { return harness.Republish(ctx, first) },
	} {
		generation, err := next()
		if err != nil {
			return err
		}
		started := time.Now()
		host, err := harness.WaitApplied(ctx, generation)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(host.Report.Agent, "gantry/") || host.Report.Profile != "developer" {
			return fmt.Errorf("unexpected host report: %+v", host.Report)
		}
		fmt.Printf("  generation %d acknowledged in %s\n", generation, time.Since(started).Round(time.Millisecond))
	}
	var generations []policyapi.Generation
	if err := harness.admin(ctx, http.MethodGet, "/v1/admin/generations", nil, http.StatusOK, &generations); err != nil {
		return err
	}
	if len(generations) != 3 || generations[0].RepublishOf != first || generations[0].Hosts != 1 {
		return fmt.Errorf("unexpected generation history: %+v", generations)
	}
	return nil
}

func testPolicyFeedRollout(ctx context.Context, client *apiClient, harness *policyFeedHarness, sandboxName string, createBody []byte) error {
	peerName := sandboxName + "-org-peer"
	if len(peerName) > 64 {
		peerName = sandboxName[:64-len("-org-peer")] + "-org-peer"
	}
	var peerRequest map[string]any
	if err := json.Unmarshal(createBody, &peerRequest); err != nil {
		return err
	}
	peerRequest["name"] = peerName
	peerBody, err := json.Marshal(peerRequest)
	if err != nil {
		return err
	}
	peerCreated := true
	defer func() {
		if !peerCreated {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, _, _, _ = client.do(cleanup, http.MethodDelete, "/v1/sandboxes/"+peerName, nil, nil)
	}()
	status, body, _, err := client.do(ctx, http.MethodPost, "/v1/sandboxes", peerBody, map[string]string{"Idempotency-Key": "policy-peer-create-1"})
	if err != nil {
		return err
	}
	if err := expectStatus(status, body, http.StatusCreated); err != nil {
		return fmt.Errorf("create policy-feed peer: %w", err)
	}

	before := make(map[string]managerapi.Sandbox, 2)
	for _, name := range []string{sandboxName, peerName} {
		status, body, _, err = client.do(ctx, http.MethodGet, "/v1/sandboxes/"+name, nil, nil)
		if err != nil {
			return err
		}
		if err := expectStatus(status, body, http.StatusOK); err != nil {
			return err
		}
		var current managerapi.Sandbox
		if err := json.Unmarshal(body, &current); err != nil {
			return err
		}
		before[name] = current
	}

	// Every generation must reach both sandboxes live: same VM processes,
	// working exec, and the published revision.
	expectLive := func(revision string) error {
		for _, name := range []string{sandboxName, peerName} {
			status, body, _, err := client.do(ctx, http.MethodGet, "/v1/sandboxes/"+name+"/policy", nil, nil)
			if err != nil {
				return err
			}
			if err := expectStatus(status, body, http.StatusOK); err != nil {
				return err
			}
			var current managerapi.OrganizationPolicy
			if err := json.Unmarshal(body, &current); err != nil {
				return err
			}
			if !current.Managed || current.Info == nil || current.Info.Organization != policyFeedOrganization || current.Info.Profile != "developer" || current.Info.Revision != revision {
				return fmt.Errorf("unexpected feed policy for %s (want revision %s): %+v", name, revision, current.Info)
			}
			status, body, _, err = client.do(ctx, http.MethodGet, "/v1/sandboxes/"+name, nil, nil)
			if err != nil {
				return err
			}
			if err := expectStatus(status, body, http.StatusOK); err != nil {
				return err
			}
			var after managerapi.Sandbox
			if err := json.Unmarshal(body, &after); err != nil {
				return err
			}
			if after.State != "running" || after.PID == 0 || after.PID != before[name].PID {
				return fmt.Errorf("organization-wide policy feed changed %s during live update: before=%+v after=%+v", name, before[name], after)
			}
			if err := expectExec(ctx, client, name, []byte(`{"argv":["/bin/sh","-c","printf policy-feed"]}`), 0, "policy-feed"); err != nil {
				return err
			}
		}
		return nil
	}
	rollout := func(label string, publish func() (uint64, error), revision string) error {
		generation, err := publish()
		if err != nil {
			return err
		}
		host, err := harness.WaitApplied(ctx, generation)
		if err != nil {
			return fmt.Errorf("%s: wait for aggregate feed acknowledgement: %w", label, err)
		}
		if !strings.HasPrefix(host.Report.Agent, "gantry/") || host.Report.Profile != "developer" || host.AcknowledgedAt == nil {
			return fmt.Errorf("%s: unexpected host report: %+v / %+v", label, host, host.Report)
		}
		if err := expectLive(revision); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		return nil
	}
	var first uint64
	if err := rollout("first generation", func() (uint64, error) {
		var err error
		first, err = harness.Publish(ctx, "e2e-r1")
		return first, err
	}, "e2e-r1"); err != nil {
		return err
	}
	if err := rollout("updated generation", func() (uint64, error) { return harness.Publish(ctx, "e2e-r2") }, "e2e-r2"); err != nil {
		return err
	}
	if err := rollout("rollback", func() (uint64, error) { return harness.Republish(ctx, first) }, "e2e-r1"); err != nil {
		return err
	}
	var overview policyapi.Overview
	if err := harness.admin(ctx, http.MethodGet, "/v1/admin/overview", nil, http.StatusOK, &overview); err != nil {
		return err
	}
	if overview.Latest != 3 || overview.Rollout == nil || overview.Rollout.Rings[0].Acknowledged != 1 || overview.Hosts.Current != 1 {
		return fmt.Errorf("unexpected policy-service overview after rollback: %+v rollout %+v", overview, overview.Rollout)
	}

	clear, _ := json.Marshal(managerapi.OrganizationPolicyRequest{Clear: true})
	status, body, _, err = client.do(ctx, http.MethodPut, "/v1/sandboxes/"+sandboxName+"/policy", clear, map[string]string{"Idempotency-Key": "policy-clear-refused-1"})
	if err != nil {
		return err
	}
	if status != http.StatusConflict || !strings.Contains(string(body), "organization-wide policy feed controls") {
		return fmt.Errorf("organization-wide policy clear was not refused: status=%d body=%s", status, body)
	}

	status, body, _, err = client.do(ctx, http.MethodDelete, "/v1/sandboxes/"+peerName, nil, map[string]string{"Idempotency-Key": "policy-peer-delete-1"})
	if err != nil {
		return err
	}
	if err := expectStatus(status, body, http.StatusOK); err != nil {
		return err
	}
	peerCreated = false
	return nil
}
