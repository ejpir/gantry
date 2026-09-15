package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/policy"
)

func (h *harness) offline(ctx context.Context) error {
	f := h.fixtures
	text, err := h.expect(ctx, "signed bundle verifies", 0, `"organization":"e2e-org"`, f.policyArgs("verify", f.good)...)
	if err != nil {
		return err
	}
	var info policy.SnapshotInfo
	if err := json.Unmarshal([]byte(text), &info); err != nil || info.Profile != "dev" || info.Revision != "fixture-1" {
		return fmt.Errorf("verification returned incorrect provenance: %s", text)
	}
	for _, tc := range []struct{ name, path, key, profile, reason string }{
		{"tampered", f.tampered, f.publicKey, "dev", "verify organization bundle"},
		{"unsigned", f.unsigned, f.publicKey, "dev", "must contain signed data.json"},
		{"wrong-key", f.good, f.wrongKey, "dev", "verify organization bundle"},
		{"unknown-profile", f.good, f.publicKey, "missing", "does not exist"},
		{"expired", f.expired, f.publicKey, "dev", "expired"},
	} {
		if _, err := h.expect(ctx, tc.name+" bundle refused", 1, tc.reason, "policy", "verify", "-bundle", tc.path, "-key", tc.key, "-profile", tc.profile); err != nil {
			return err
		}
		if !h.opts.cliOnly {
			flags := []string{"-org-policy", tc.path, "-org-policy-key", tc.key, "-policy-profile", tc.profile}
			name := "pol-bad-" + tc.name
			if err := h.startDenied(ctx, name, tc.reason, flags...); err != nil {
				return err
			}
			for _, path := range []string{filepath.Join(h.state, name), filepath.Join(filepath.Dir(h.state), "rwlayers", name+".ext4")} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					return fmt.Errorf("rejected %s created state at %s", tc.name, path)
				}
			}
			h.pass(tc.name + " fails before creating sandbox state")
		}
	}
	for _, tc := range []struct {
		action, resource, effect string
		code                     int
	}{
		{policy.MCPCall, `{"server":"mock","tool":"read"}`, "allow", 0},
		{policy.MCPCall, `{"server":"mock","tool":"listed"}`, "deny", 1},
		{policy.MCPList, `{"server":"mock","tool":"hidden"}`, "deny", 1},
		{policy.CredentialUse, `{"host":"git.allowed.test"}`, "allow", 0},
		{policy.CredentialUse, `{"host":"git.denied.test"}`, "deny", 1},
	} {
		args := append(f.policyArgs("check", f.good), "-action", tc.action, "-resource", tc.resource)
		if _, err := h.expect(ctx, "offline "+tc.action+" "+tc.effect, tc.code, `"effect":"`+tc.effect+`"`, args...); err != nil {
			return err
		}
	}
	if !h.opts.cliOnly {
		flags := append(f.flags(f.good, f.publicKey), "-oauth-custody")
		if err := h.startDenied(ctx, "pol-bad-custody", "does not support OAuth custody", flags...); err != nil {
			return err
		}
	}
	return nil
}

func (h *harness) enforcement(ctx context.Context, allowed, denied *endpoint) error {
	f := h.fixtures
	if err := allowed.healthy(5 * time.Second); err != nil {
		return err
	}
	if err := denied.healthy(5 * time.Second); err != nil {
		return err
	}
	baselineDenied := denied.connections.Load()
	for _, tc := range []struct{ name, spec, reason string }{
		{"pol-deny-mount", "code=" + f.forbidden + ",ro", "denied mount.read"},
		{"pol-deny-write", "code=" + f.allowed, "denied mount.write"},
	} {
		if err := h.startDenied(ctx, tc.name, tc.reason, append(f.flags(f.good, f.publicKey), "-share", tc.spec)...); err != nil {
			return err
		}
	}
	flags := append(f.flags(f.good, f.publicKey), "-allow-local-net", "-share", "code="+f.allowed+",ro", "-mcp", "-mcp-fs-root", "/tmp",
		"-mcp-remote", "name=mock,url="+allowed.URL+"/mcp,allow=*",
		"-mcp-remote", "name=blocked,url="+denied.URL+"/mcp,allow=*",
		"-secret", "OPA_ALLOW@git.allowed.test", "-secret", "OPA_DENY@git.denied.test")
	if err := h.start(ctx, "pol-main", flags...); err != nil {
		return err
	}
	bootLog, err := os.ReadFile(filepath.Join(h.state, "pol-main", "daemon.log"))
	if err != nil {
		return err
	}
	if !strings.Contains(string(bootLog), "guest tools delivered via share") {
		return fmt.Errorf("governed bootstrap did not use the isolated helper payload share")
	}
	h.pass("guest helper delivered without granting access to host staging directories")
	if _, err := h.expect(ctx, "helper tag does not bypass mount policy", 1, "denied mount.read", "share", "add", "pol-main", "gantry-tools="+f.forbidden+",ro"); err != nil {
		return err
	}
	if _, err := h.guest(ctx, "guest probe prerequisites", probePrerequisites, 0, "OPA-PROBES-READY"); err != nil {
		return err
	}
	if _, err := h.guest(ctx, "approved host mount readable", "cat /host/code/marker", 0, "OPA-SHARE-OK"); err != nil {
		return err
	}
	if _, err := h.guest(ctx, "read-only mount enforced", `if echo BAD > /host/code/unexpected-write; then exit 0; else echo OPA-WRITE-DENIED; exit 23; fi`, deniedExit, "OPA-WRITE-DENIED"); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(f.allowed, "unexpected-write")); !os.IsNotExist(err) {
		return fmt.Errorf("read-only write reached host")
	}
	if _, err := h.expect(ctx, "live read-only mount accepted", 0, "added", "share", "add", "--ephemeral", "pol-main", "extra="+f.extraAllowed+",ro"); err != nil {
		return err
	}
	if _, err := h.guest(ctx, "live export visible in guest", "cat /host/extra/marker", 0, "OPA-SHARE-OK"); err != nil {
		return err
	}
	if _, err := h.expect(ctx, "live forbidden mount denied", 1, "denied mount.read", "share", "add", "pol-main", "forbidden="+f.forbidden+",ro"); err != nil {
		return err
	}
	if _, err := h.expect(ctx, "live writable replacement denied", 1, "denied mount.write", "share", "add", "--replace", "pol-main", "code="+f.allowed); err != nil {
		return err
	}
	if _, err := h.guest(ctx, "denied replacement leaves old export intact", "cat /host/code/marker; test ! -e /host/forbidden", 0, "OPA-SHARE-OK"); err != nil {
		return err
	}
	if err := h.network(ctx, allowed, denied, "initial"); err != nil {
		return err
	}
	if err := h.credentials(ctx, false); err != nil {
		return err
	}
	if err := h.mcp(ctx, allowed, denied); err != nil {
		return err
	}
	if denied.connections.Load() != baselineDenied {
		return fmt.Errorf("denied guest/MCP endpoint received a connection")
	}
	h.pass("denied egress and MCP dials never reach healthy host listener")

	// Local rules are allowed to narrow but never widen the organization plan.
	if _, err := h.expect(ctx, "live local-policy reset accepted", 0, "active", "net-policy", "default", "--allow-local-net", "pol-main"); err != nil {
		return err
	}
	if err := h.network(ctx, allowed, denied, "after local reset"); err != nil {
		return err
	}
	local := filepath.Join(h.root, "allow-all.json")
	if err := writeFile(local, []byte(`{"default":"allow","allowLocal":true,"rules":[{"action":"allow"}]}`), 0600); err != nil {
		return err
	}
	if _, err := h.expect(ctx, "live broad local allow accepted", 0, "active", "net-policy", "set", "pol-main", local); err != nil {
		return err
	}
	if err := h.network(ctx, allowed, denied, "after broad local allow"); err != nil {
		return err
	}
	if err := h.credentials(ctx, false); err != nil {
		return err
	}
	if _, err := h.expect(ctx, "active rule inspection retains org guard", 0, "org:e2e-org:deny-port", "net-policy", "show", "pol-main"); err != nil {
		return err
	}
	pidPath := filepath.Join(h.state, "pol-main", "vmm.pid")
	pidBefore, err := os.ReadFile(pidPath)
	if err != nil {
		return err
	}
	if _, err := h.expect(ctx, "running org-policy replacement applies live", 0, "active now", "policy", "set", "pol-main", "-bundle", f.good, "-key", f.publicKey, "-profile", "dev"); err != nil {
		return err
	}
	pidAfter, err := os.ReadFile(pidPath)
	if err != nil {
		return err
	}
	if string(pidAfter) != string(pidBefore) {
		return fmt.Errorf("live organization-policy replacement changed sandbox PID: %q -> %q", pidBefore, pidAfter)
	}
	h.pass("live organization-policy replacement keeps the sandbox process")

	audit, err := h.expect(ctx, "OPA decisions available in live audit", 0, `"organization":"e2e-org"`, "audit", "pol-main")
	if err != nil {
		return err
	}
	if !strings.Contains(audit, `"revision":"fixture-1"`) || !strings.Contains(audit, `"action":"mcp.tools.call"`) {
		return fmt.Errorf("audit missing revision or MCP decision")
	}
	auditData := []string{audit}
	for _, name := range []string{"daemon.log", "audit.log", "sandbox.json"} {
		raw, err := os.ReadFile(filepath.Join(h.state, "pol-main", name))
		if err != nil {
			return fmt.Errorf("read audit artifact %s: %w", name, err)
		}
		auditData = append(auditData, string(raw))
	}
	for _, data := range auditData {
		for _, value := range append(append([]string{}, h.secrets...), argumentCanary) {
			if strings.Contains(data, value) {
				return fmt.Errorf("policy audit/config leaked a credential or argument")
			}
		}
	}
	h.pass("audit/config contain no credential values or MCP arguments")

	// A restart must use pinned signed bytes and key, not reopen these files.
	if err := os.WriteFile(f.good, []byte("changed bundle source"), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(f.publicKey, []byte("changed key source"), 0600); err != nil {
		return err
	}
	if _, err := h.expect(ctx, "stop before pinned restart", 0, "", "stop", "pol-main"); err != nil {
		return err
	}
	persisted, err := h.expect(ctx, "OPA decisions available in stopped audit", 0, `"organization":"e2e-org"`, "audit", "pol-main")
	if err != nil {
		return err
	}
	for _, field := range []string{`"revision":"fixture-1"`, `"action":"mcp.tools.call"`, `"effect":"allow"`, `"effect":"deny"`} {
		if !strings.Contains(persisted, field) {
			return fmt.Errorf("stopped policy audit missing %s", field)
		}
	}
	for _, value := range append(append([]string{}, h.secrets...), argumentCanary) {
		if strings.Contains(persisted, value) {
			return fmt.Errorf("stopped policy audit leaked a credential or argument")
		}
	}
	if _, err := h.expect(ctx, "restart survives changed source bundle and key", 0, "", "resume", "pol-main"); err != nil {
		return err
	}
	if err := h.network(ctx, allowed, denied, "after pinned restart"); err != nil {
		return err
	}
	if _, err := h.expect(ctx, "saved snapshot still verifies", 0, `"revision":"fixture-1"`, "policy", "show", "pol-main"); err != nil {
		return err
	}
	if err := writeFile(f.publicKey, publicPEM(f.key), 0600); err != nil {
		return err
	}

	strict := policy.Profile{}
	updated, err := f.sign("updated", "fixture-2", time.Now().Add(time.Hour), strict)
	if err != nil {
		return err
	}
	pidBefore, err = os.ReadFile(pidPath)
	if err != nil {
		return err
	}
	if _, err := h.expect(ctx, "running bundle update accepted", 0, "active now", "policy", "set", "pol-main", "-bundle", updated, "-key", f.publicKey, "-profile", "dev"); err != nil {
		return err
	}
	pidAfter, err = os.ReadFile(pidPath)
	if err != nil {
		return err
	}
	if string(pidAfter) != string(pidBefore) {
		return fmt.Errorf("live restrictive policy changed sandbox PID: %q -> %q", pidBefore, pidAfter)
	}
	h.pass("restrictive live update keeps the sandbox process")
	if _, err := h.expect(ctx, "new revision active", 0, `"revision":"fixture-2"`, "policy", "show", "pol-main"); err != nil {
		return err
	}
	if _, err := h.guest(ctx, "updated bundle revokes prior network grant", httpProbe(allowed.guestURL()), deniedExit, "OPA-NET-DENIED"); err != nil {
		return err
	}
	if _, err := h.guest(ctx, "updated bundle revokes mounted share", "cat /host/code/marker", 1, ""); err != nil {
		return err
	}
	if _, err := h.expect(ctx, "revoked share reports policy state", 0, "policy-denied", "share", "ls", "pol-main"); err != nil {
		return err
	}
	if err := h.credentialGrants(ctx, []bool{false, false}); err != nil {
		return err
	}
	mcpListing, err := h.command(ctx, "", "mcp", "tools", "pol-main")
	if err != nil {
		return err
	}
	if strings.Contains(mcpListing.output, "mock__") || mcpListing.code != 0 && !strings.Contains(strings.ToLower(mcpListing.output), "denied") {
		return fmt.Errorf("live organization policy did not revoke MCP tools: %s", h.redact(mcpListing.output))
	}
	h.pass("updated bundle revokes MCP tools")

	pidBefore, err = os.ReadFile(pidPath)
	if err != nil {
		return err
	}
	if _, err := h.expect(ctx, "host can clear running snapshot", 0, "active now", "policy", "clear", "pol-main"); err != nil {
		return err
	}
	pidAfter, err = os.ReadFile(pidPath)
	if err != nil {
		return err
	}
	if string(pidAfter) != string(pidBefore) {
		return fmt.Errorf("live organization-policy clear changed sandbox PID: %q -> %q", pidBefore, pidAfter)
	}
	h.pass("live organization-policy clear keeps the sandbox process")
	if _, err := h.expect(ctx, "unmanaged state explicit", 0, "unmanaged", "policy", "show", "pol-main"); err != nil {
		return err
	}
	if _, err := h.guest(ctx, "clearing snapshot restores local network behavior", httpProbe(denied.guestURL()), 0, denied.marker); err != nil {
		return err
	}
	if _, err := h.guest(ctx, "clearing snapshot restores mounted share", "cat /host/code/marker", 0, "OPA-SHARE-OK"); err != nil {
		return err
	}
	if err := h.credentials(ctx, true); err != nil {
		return err
	}
	return nil
}

func (h *harness) network(ctx context.Context, allowed, denied *endpoint, label string) error {
	if _, err := h.guest(ctx, label+": permitted network tuple", httpProbe(allowed.guestURL()), 0, allowed.marker); err != nil {
		return err
	}
	before := denied.connections.Load()
	if _, err := h.guest(ctx, label+": deny beats broad allow", httpProbe(denied.guestURL()), deniedExit, "OPA-NET-DENIED"); err != nil {
		return err
	}
	if denied.connections.Load() != before {
		return fmt.Errorf("%s: denied connection reached listener", label)
	}
	if _, err := h.guest(ctx, label+": permitted built-in DNS name", dnsProbe("gateway.containers.internal"), 0, "192.168.127.1"); err != nil {
		return err
	}
	if _, err := h.guest(ctx, label+": unlisted built-in DNS name blocked", dnsProbe("host.containers.internal"), deniedExit, "OPA-DNS-DENIED"); err != nil {
		return err
	}
	// A broken network must not count as a passing negative check.
	_, err := h.guest(ctx, label+": positive control still reachable", httpProbe(allowed.guestURL()), 0, allowed.marker)
	return err
}
func (h *harness) credentials(ctx context.Context, unmanaged bool) error {
	return h.credentialGrants(ctx, []bool{true, unmanaged})
}

func (h *harness) credentialGrants(ctx context.Context, grants []bool) error {
	hosts := []string{"git.allowed.test", "git.denied.test"}
	if len(grants) != len(hosts) {
		return fmt.Errorf("credential grant fixture has %d entries, want %d", len(grants), len(hosts))
	}
	for i, host := range hosts {
		query := fmt.Sprintf("printf 'protocol=https\\nhost=%s\\n\\n' | /run/gantry/bin/credhelper get", host)
		text, err := h.guest(ctx, "credential helper executes for "+host, query, 0, "")
		if err != nil {
			return err
		}
		if grants[i] && !strings.Contains(text, "password="+h.secrets[i]) {
			return fmt.Errorf("approved bound credential missing for %s", host)
		}
		if !grants[i] && (strings.Contains(text, "password=") || strings.Contains(text, h.secrets[i])) {
			return fmt.Errorf("organization denied credential was released")
		}
		h.pass(fmt.Sprintf("credential grant for %s = %t", host, grants[i]))
	}
	return nil
}

func (h *harness) expiry(ctx context.Context, window time.Duration) error {
	f := h.fixtures
	deadline := time.Now().Add(window)
	path, err := f.sign("short", "expiry-1", deadline, f.profile)
	if err != nil {
		return err
	}
	if err := h.start(ctx, "pol-expiry", append(f.flags(path, f.publicKey), "-net=false", "-share", "code="+f.allowed+",ro")...); err != nil {
		return err
	}
	if _, err := h.expect(ctx, "short-lived snapshot usable before expiry", 0, "OPA-SHARE-OK", "exec", "pol-expiry", "--", "cat", "/host/code/marker"); err != nil {
		return err
	}
	timer := time.NewTimer(max(0, time.Until(deadline)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	pollDeadline := time.Now().Add(45 * time.Second)
	for {
		r, err := h.command(ctx, "", "ls")
		if err != nil {
			return err
		}
		if r.code != 0 {
			return fmt.Errorf("cannot inspect expiring sandbox: %s", h.redact(r.output))
		}
		if sandboxState(r.output, "pol-expiry") == "stopped" {
			break
		}
		if time.Now().After(pollDeadline) {
			return fmt.Errorf("expired sandbox did not stop")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	log, err := os.ReadFile(filepath.Join(h.state, "pol-expiry", "daemon.log"))
	if err != nil {
		return err
	}
	if !strings.Contains(string(log), "organization policy expired") {
		return fmt.Errorf("sandbox stopped without policy-expiry attribution")
	}
	h.pass("policy expiry automatically stops a previously usable sandbox")
	if _, err := h.expect(ctx, "expired saved snapshot cannot restart", 1, "expired", "resume", "pol-expiry"); err != nil {
		return err
	}
	if _, err := h.expect(ctx, "expired policy show never claims valid/unmanaged", 1, "expired", "policy", "show", "pol-expiry"); err != nil {
		return err
	}
	return nil
}
func sandboxState(output, name string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == name {
			return fields[1]
		}
	}
	return ""
}
