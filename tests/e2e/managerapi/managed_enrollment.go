package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	policyapi "github.com/ejpir/gantry/api/policyservice"
)

// testManagedFeedEnrollment exercises the desktop's two independent API
// connections against a second real manager. It needs no VM and runs in both
// API-only and field-host modes, including Windows.
func testManagedFeedEnrollment(ctx context.Context, harness *policyFeedHarness, gantry, repo, work string, env []string) error {
	work = filepath.Join(work, "managed-enrollment")
	if err := os.MkdirAll(work, 0o700); err != nil {
		return err
	}
	managerEnv := environmentFrom(env, map[string]string{
		"GANTRY_HOME":           filepath.Join(work, "sandboxes"),
		"GANTRY_MANAGER_SOCKET": filepath.Join(work, "manager.sock"),
	})
	transport, err := setupTLSHarness(ctx, repo, managerEnv, gantry, work)
	if err != nil {
		return err
	}
	logPath := filepath.Join(work, "manager.log")
	args := []string{"serve", "-listen", "tls://" + transport.address, "--self-signed", "--token-file", transport.tokenPath}
	var process *exec.Cmd
	var exited chan struct{}
	var processErr error
	stop := func() {
		if process == nil {
			return
		}
		_ = process.Process.Signal(os.Interrupt)
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			_ = process.Process.Kill()
			<-exited
		}
		process = nil
	}
	defer stop()
	start := func(extra ...string) (*apiClient, error) {
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, err
		}
		process = exec.CommandContext(ctx, gantry, append(append([]string(nil), args...), extra...)...)
		process.Dir, process.Env, process.Stdout, process.Stderr = repo, managerEnv, logFile, logFile
		if err := process.Start(); err != nil {
			_ = logFile.Close()
			process = nil
			return nil, err
		}
		exited = make(chan struct{})
		go func() {
			processErr = process.Wait()
			_ = logFile.Close()
			close(exited)
		}()
		readyCtx, cancelReady := context.WithTimeout(ctx, 30*time.Second)
		defer cancelReady()
		var client *apiClient
		for client == nil {
			client, err = newPinnedTLSClient(transport.address, filepath.Join(work, "serve", "ca.crt"), logPath)
			if err == nil {
				break
			}
			select {
			case <-exited:
				return nil, fmt.Errorf("managed manager exited before TLS readiness: %w (%v)", processErr, err)
			case <-readyCtx.Done():
				return nil, fmt.Errorf("managed manager TLS startup: %w", readyCtx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
		client.token = transport.token
		if err := waitForHealth(readyCtx, client, exited, func() error { return processErr }); err != nil {
			return nil, err
		}
		return client, nil
	}
	client, err := start()
	if err != nil {
		return err
	}
	call := func(method, route string, request any, want int, result any) ([]byte, error) {
		var data []byte
		if request != nil {
			var err error
			data, err = json.Marshal(request)
			if err != nil {
				return nil, err
			}
		}
		status, body, _, err := client.do(ctx, method, route, data, nil)
		if err != nil {
			return nil, err
		}
		if err := expectStatus(status, body, want); err != nil {
			return nil, err
		}
		if result != nil {
			if err := json.Unmarshal(body, result); err != nil {
				return nil, err
			}
		}
		return body, nil
	}
	const route = "/v1/policy-feed/enrollment"
	unauthorized := *client
	unauthorized.token = ""
	status, body, _, err := unauthorized.do(ctx, http.MethodGet, route, nil, nil)
	if err != nil || status != http.StatusForbidden {
		return fmt.Errorf("feed enrollment route bypassed manager authentication: %d %v %s", status, err, body)
	}
	var health managerapi.Health
	if _, err := call(http.MethodGet, "/v1/health", nil, http.StatusOK, &health); err != nil {
		return err
	}
	if !slicesContains(health.Capabilities, "policy-feed-enroll-v1") {
		return errors.New("managed manager has no enrollment capability")
	}
	// Neither the service's administrator token nor the manager bearer token
	// is sent to the other endpoint.
	var overview policyapi.Overview
	if err := harness.admin(ctx, http.MethodGet, "/v1/admin/overview", nil, http.StatusOK, &overview); err != nil {
		return err
	}
	const name = "managed-e2e"
	prepare := managerapi.PolicyFeedPrepareRequest{
		Host: name, Organization: overview.Organization, Profile: "developer",
		URL: overview.FeedURL, PublicKeyFingerprint: overview.PublicKeyFingerprint,
		CAFingerprint: overview.CAFingerprint,
	}
	var first, retry managerapi.PolicyFeedPrepareResponse
	firstBody, err := call(http.MethodPost, route, prepare, http.StatusCreated, &first)
	if err != nil {
		return err
	}
	if _, err := call(http.MethodPost, route, prepare, http.StatusOK, &retry); err != nil {
		return err
	}
	if first.ID == "" || first.ID != retry.ID || first.CSR != retry.CSR || !strings.Contains(first.CSR, "BEGIN CERTIFICATE REQUEST") {
		return errors.New("manager did not retain the same private host request across retries")
	}
	var pending managerapi.PolicyFeedStatus
	if _, err := call(http.MethodGet, route, nil, http.StatusOK, &pending); err != nil {
		return err
	}
	if pending.EnrollmentState != "awaiting-enrollment" || pending.ConfigPath != "" {
		return fmt.Errorf("manager reported a pending CSR as active: %+v", pending)
	}
	keyPath := filepath.Join(work, "manager-state", "feed-enrollment", policyapi.HostKeyFile)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	if bytes.Contains(firstBody, key) || bytes.Contains([]byte(first.CSR), key) {
		return errors.New("manager response exported the host key")
	}
	info, err := os.Stat(keyPath)
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("host key was not private: %v", err)
	}
	// An unsigned, unmatched feed config is refused before installation.
	var enrolled policyapi.Enrollment
	if err := harness.admin(ctx, http.MethodPost, "/v1/admin/hosts", policyapi.EnrollRequest{
		Name: name, Profile: "developer", Ring: "canary", CSR: first.CSR,
	}, http.StatusCreated, &enrolled); err != nil {
		return err
	}
	if enrolled.Host.Name != name || len(enrolled.Files) != 4 {
		return errors.New("policy service enrolled a different host or returned incomplete files")
	}
	install := managerapi.PolicyFeedInstallRequest{ID: first.ID, Files: enrolled.Files}
	badFiles := make(map[string]string, len(install.Files))
	for file, value := range install.Files {
		badFiles[file] = value
	}
	badFiles[policyapi.FeedConfigFile] = strings.Replace(badFiles[policyapi.FeedConfigFile], `"profile": "developer"`, `"profile": "unapproved"`, 1)
	if badFiles[policyapi.FeedConfigFile] == install.Files[policyapi.FeedConfigFile] {
		return errors.New("test did not alter feed profile")
	}
	if _, err := call(http.MethodPost, route+"/install", managerapi.PolicyFeedInstallRequest{ID: first.ID, Files: badFiles}, http.StatusUnprocessableEntity, nil); err != nil {
		return err
	}
	var staged managerapi.PolicyFeedStatus
	installBody, err := call(http.MethodPost, route+"/install", install, http.StatusOK, &staged)
	if err != nil {
		return err
	}
	if staged.EnrollmentState != "restart-required" || staged.ConfigPath == "" || bytes.Contains(installBody, key) {
		return fmt.Errorf("manager did not stage the feed without exposing the key: %+v", staged)
	}
	if _, err := call(http.MethodPost, route+"/install", install, http.StatusOK, &staged); err != nil {
		return err
	}
	stop()
	// A cold manager must refuse to start ungoverned even when the caller
	// explicitly supplies its original TLS and token flags.
	cmd := exec.CommandContext(ctx, gantry, args...)
	cmd.Dir, cmd.Env = repo, managerEnv
	output, err := cmd.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("saved organization policy-feed state")) {
		return fmt.Errorf("ungoverned restart was not refused: %v: %s", err, output)
	}
	wrong := exec.CommandContext(ctx, gantry, append(append([]string(nil), args...), "-policy-feed", harness.configPath)...)
	wrong.Dir, wrong.Env = repo, managerEnv
	output, err = wrong.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("staged organization feed requires")) {
		return fmt.Errorf("different-feed restart was not refused: %v: %s", err, output)
	}
	client, err = start("-policy-feed", staged.ConfigPath)
	if err != nil {
		return err
	}
	var configured managerapi.PolicyFeedStatus
	if _, err := call(http.MethodGet, route, nil, http.StatusOK, &configured); err != nil {
		return err
	}
	if configured.EnrollmentState != "configured" || configured.ConfigPath != staged.ConfigPath {
		return fmt.Errorf("manager did not load the staged feed: %+v", configured)
	}
	return nil
}

func slicesContains(haystack []string, needle string) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}
	return false
}
